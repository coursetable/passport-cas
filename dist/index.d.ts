import { Strategy as BaseStrategy } from "passport-strategy";
import express from "express";
type CasInfo = {
    user: string;
    attributes?: {
        [key in string]: string | string[];
    };
};
type VersionOptions = "CAS1.0" | "CAS2.0" | "CAS2.0-with-saml" | "CAS3.0" | "CAS3.0-with-saml";
type VerifyDoneCallback = (err: any, user?: any, info?: any) => void;
type VerifyFunction = (login: CasInfo, done: VerifyDoneCallback) => void;
export declare class Strategy extends BaseStrategy {
    name: string;
    private version;
    private ssoBase;
    private serverBaseURL?;
    private validateURI;
    private callbackURL?;
    private _verify;
    constructor(options: {
        version?: VersionOptions;
        ssoBaseURL: string;
        serverBaseURL?: string;
        validateURL?: string;
        callbackURL?: string;
        useSaml?: boolean;
        passReqToCallback?: boolean;
    }, verify: VerifyFunction);
    authenticate(req: express.Request, options?: {
        /** Preserve the original query parameters. Default true. */
        copyQueryParameters?: boolean;
    }): void;
    /**
     * Generate the "service" parameter for the CAS callback URL.
     */
    private service;
}
export default Strategy;
