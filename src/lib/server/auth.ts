import { Issuer, BaseClient, type UserinfoResponse, TokenSet, custom } from "openid-client";
import { addHours, addWeeks } from "date-fns";
import {
	COOKIE_NAME,
	OPENID_CLIENT_ID,
	OPENID_CLIENT_SECRET,
	OPENID_PROVIDER_URL,
	OPENID_SCOPES,
	OPENID_NAME_CLAIM,
	OPENID_TOLERANCE,
	OPENID_RESOURCE,
	OPENID_CONFIG,
	OPENID_TOKEN_ENDPOINT,
	OPENID_INFO_ENDPOINT
} from "$env/static/private";
import { sha256 } from "$lib/utils/sha256";
import { z } from "zod";
import { dev } from "$app/environment";
import type { Cookies } from "@sveltejs/kit";
import { collections } from "./database";
import JSON5 from "json5";
import { AuthenticationClient } from "authing-js-sdk";
import axios from 'axios';
import qs from "querystring";

export interface OIDCSettings {
	redirectURI: string;
}

export interface OIDCUserInfo {
	token: TokenSet;
	userData: UserinfoResponse;
}

const stringWithDefault = (value: string) =>
	z
		.string()
		.default(value)
		.transform((el) => (el ? el : value));

export const OIDConfig = z
	.object({
		CLIENT_ID: stringWithDefault(OPENID_CLIENT_ID),
		CLIENT_SECRET: stringWithDefault(OPENID_CLIENT_SECRET),
		PROVIDER_URL: stringWithDefault(OPENID_PROVIDER_URL),
		SCOPES: stringWithDefault(OPENID_SCOPES),
		NAME_CLAIM: stringWithDefault(OPENID_NAME_CLAIM).refine(
			(el) => !["preferred_username", "email", "picture", "sub"].includes(el),
			{ message: "nameClaim cannot be one of the restricted keys." }
		),
		TOLERANCE: stringWithDefault(OPENID_TOLERANCE),
		RESOURCE: stringWithDefault(OPENID_RESOURCE),
		TOKEN_ENDPOINT: stringWithDefault(OPENID_TOKEN_ENDPOINT),
		INFO_ENDPOINT: stringWithDefault(OPENID_INFO_ENDPOINT),
	})
	.parse(JSON5.parse(OPENID_CONFIG));

export const requiresUser = !!OIDConfig.CLIENT_ID && !!OIDConfig.CLIENT_SECRET;

export function refreshSessionCookie(cookies: Cookies, sessionId: string) {
	cookies.set(COOKIE_NAME, sessionId, {
		path: "/",
		// So that it works inside the space's iframe
		sameSite: dev ? "lax" : "none",
		secure: !dev,
		httpOnly: true,
		expires: addWeeks(new Date(), 2),
	});
}

export async function findUser(sessionId: string) {
	const session = await collections.sessions.findOne({ sessionId });

	if (!session) {
		return null;
	}

	return await collections.users.findOne({ _id: session.userId });
}
export const authCondition = (locals: App.Locals) => {
	return locals.user
		? { userId: locals.user._id }
		: { sessionId: locals.sessionId, userId: { $exists: false } };
};

/**
 * Generates a CSRF token using the user sessionId. Note that we don't need a secret because sessionId is enough.
 */
export async function generateCsrfToken(sessionId: string, redirectUrl: string): Promise<string> {
	const data = {
		expiration: addHours(new Date(), 1).getTime(),
		redirectUrl,
	};

	return Buffer.from(
		JSON.stringify({
			data,
			signature: await sha256(JSON.stringify(data) + "##" + sessionId),
		})
	).toString("base64");
}

async function getOIDCClient(settings: OIDCSettings): Promise<BaseClient | AuthenticationClient> {

	if (OIDConfig.PROVIDER_URL.includes("authing")) {
		return new AuthenticationClient({
			appId: OIDConfig.CLIENT_ID, // 应用 ID
			secret: OIDConfig.CLIENT_SECRET,// 应用 Secret
			appHost: OIDConfig.PROVIDER_URL,// 应用对应的用户池域名
			redirectUri: settings.redirectURI,// 认证完成后的重定向目标 URL
		});
	} else {
		const issuer = await Issuer.discover(OIDConfig.PROVIDER_URL);

		return new issuer.Client({
			client_id: OIDConfig.CLIENT_ID,
			client_secret: OIDConfig.CLIENT_SECRET,
			redirect_uris: [settings.redirectURI],
			response_types: ["code"],
			[custom.clock_tolerance]: OIDConfig.TOLERANCE || undefined,
		});
	}

}

export async function getOIDCAuthorizationUrl(
	settings: OIDCSettings,
	params: { sessionId: string }
): Promise<string> {
	const client = await getOIDCClient(settings);
	if (OIDConfig.PROVIDER_URL.includes("authing")) {
		return (client as AuthenticationClient).buildAuthorizeUrl({
			scope: OIDConfig.SCOPES
		})

	} else {
		const csrfToken = await generateCsrfToken(params.sessionId, settings.redirectURI)
		return (client as BaseClient).authorizationUrl({
			scope: OIDConfig.SCOPES,
			state: csrfToken,
			resource: OIDConfig.RESOURCE || undefined,
		});
	}

}

export async function getOIDCUserData(settings: OIDCSettings, code: string) {
	const client = await getOIDCClient(settings);
	if (OIDConfig.PROVIDER_URL.includes("authing")) {
		console.log("code:", code)
		const code2tokenResponse = await axios.post(OIDConfig.TOKEN_ENDPOINT,
			qs.stringify({
				code,
				client_id: OIDConfig.CLIENT_ID,
				client_secret: OIDConfig.CLIENT_SECRET,
				grant_type: "authorization_code",
				redirect_uri: settings.redirectURI,
			}), {headers: {"Content-Type": "application/x-www-form-urlencoded",},
			}
		);

		const token2UserInfoResponse = await axios.get(
			`${OIDConfig.INFO_ENDPOINT}?access_token=` + code2tokenResponse.data.access_token
		);

		let userData = token2UserInfoResponse.data
		userData.preferred_username = userData.email ? userData.email : userData.phone_number;
		userData.name = userData.preferred_username
		delete userData.phone_number
		delete userData.phone_number_verified
		delete userData.email_verified
		if (userData.email == null) {
			delete userData.email
		}

		return {userData};

	} else {
		const token = await (client as BaseClient).callback(settings.redirectURI, { code });
		const userData = await (client as BaseClient).userinfo(token);

		return { token, userData };
	}



}

export async function validateAndParseCsrfToken(
	token: string,
	sessionId: string
): Promise<{
	/** This is the redirect url that was passed to the OIDC provider */
	redirectUrl: string;
} | null> {
	try {
		const { data, signature } = z
			.object({
				data: z.object({
					expiration: z.number().int(),
					redirectUrl: z.string().url(),
				}),
				signature: z.string().length(64),
			})
			.parse(JSON.parse(token));
		const reconstructSign = await sha256(JSON.stringify(data) + "##" + sessionId);

		if (data.expiration > Date.now() && signature === reconstructSign) {
			return { redirectUrl: data.redirectUrl };
		}
	} catch (e) {
		console.error(e);
	}
	return null;
}
