import { redirect, error } from "@sveltejs/kit";
import { OIDConfig, getOIDCUserData, validateAndParseCsrfToken } from "$lib/server/auth";
import { z } from "zod";
import { base } from "$app/paths";
import { updateUser } from "./updateUser";
import { env } from "$env/dynamic/private";
import JSON5 from "json5";

// 提取了验证电子邮件的函数
function validateEmail(userData) {
	if (allowedUserEmails.length > 0) {
		if (!userData.email) {
			throw error(403, "User not allowed: email not returned");
		}
		const emailVerified = userData.email_verified ?? true;
		if (!emailVerified) {
			throw error(403, "User not allowed: email not verified");
		}
		if (!allowedUserEmails.includes(userData.email)) {
			throw error(403, "User not allowed");
		}
	}
}

const allowedUserEmails = z
	.array(z.string().email())
	.optional()
	.default([])
	.parse(JSON5.parse(env.ALLOWED_USER_EMAILS));

export async function load({ url, locals, cookies, request, getClientAddress }) {
	const { error: errorName, error_description: errorDescription } = z
		.object({
			error: z.string().optional(),
			error_description: z.string().optional(),
		})
		.parse(Object.fromEntries(url.searchParams.entries()));

	if (errorName) {
		throw error(400, errorName + (errorDescription ? ": " + errorDescription : ""));
	}

	const { code, state, iss } = z
		.object({
			code: z.string(),
			state: z.string(),
			iss: z.string().optional(),
		})
		.parse(Object.fromEntries(url.searchParams.entries()));

	let redirectURI;
	if (OIDConfig.PROVIDER_URL.includes("authing")) {
		redirectURI = `${url.origin}${base}/login/callback`;
	} else {
		const csrfToken = Buffer.from(state, "base64").toString("utf-8");
		const validatedToken = await validateAndParseCsrfToken(csrfToken, locals.sessionId);
		if (!validatedToken) {
			throw error(403, "Invalid or expired CSRF token");
		}
		redirectURI = validatedToken.redirectUrl;
	}

	const { userData } = await getOIDCUserData({ redirectURI: redirectURI }, code);

	validateEmail(userData);

	await updateUser({
		userData,
		locals,
		cookies,
		userAgent: request.headers.get("user-agent") ?? undefined,
		ip: getClientAddress(),
	});

	throw redirect(302, `${base}/`);
}
