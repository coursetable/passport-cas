"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Strategy = void 0;
/**
 * Cas
 */
const underscore_1 = __importStar(require("underscore"));
const url_1 = __importDefault(require("url"));
const axios_1 = __importDefault(require("axios"));
const uuid_1 = __importDefault(require("uuid"));
const passport_strategy_1 = require("passport-strategy");
const util_1 = __importDefault(require("util"));
const xml2js_1 = require("xml2js");
const verror_1 = __importDefault(require("verror"));
const parseXmlString = (xml) => {
    const xmlParseOpts = {
        trim: true,
        normalize: true,
        explicitArray: false,
        tagNameProcessors: [xml2js_1.processors.normalize, xml2js_1.processors.stripPrefix],
    };
    return new Promise((resolve, reject) => {
        (0, xml2js_1.parseString)(xml, xmlParseOpts, (err, result) => {
            if (err) {
                return reject(err);
            }
            resolve(result);
        });
    });
};
const validateResponseCas1 = async (body) => {
    const lines = body.split("\n");
    if (lines.length >= 1) {
        if (lines[0] === "no") {
            throw new Error("Authentication rejected");
        }
        else if (lines[0] === "yes" && lines.length >= 2) {
            const profile = {
                user: lines[1],
            };
            return profile;
        }
    }
    throw new Error("The response from the server was bad");
};
const validateResponseCas3 = async (body) => {
    const result = await parseXmlString(body);
    try {
        if (result.serviceresponse.authenticationfailure) {
            throw new Error("Authentication failed " +
                result.serviceresponse.authenticationfailure.$.code);
        }
        const success = result.serviceresponse.authenticationsuccess;
        if (success) {
            return success;
        }
        throw new Error("Authentication failed but success present");
    }
    catch (e) {
        throw new Error("Authentication failed - XML parsing issue");
    }
};
const validateResponseCas3saml = async (body) => {
    const result = await parseXmlString(body);
    try {
        var response = result.envelope.body.response;
        var success = response.status.statuscode["$"].Value.match(/Success$/);
        if (success) {
            let attributes = {};
            underscore_1.default.each(response.assertion.attributestatement.attribute, function (attribute) {
                attributes[attribute["$"].AttributeName.toLowerCase()] =
                    attribute.attributevalue;
            });
            const profile = {
                user: response.assertion.authenticationstatement.subject.nameidentifier,
                attributes: attributes,
            };
            return profile;
        }
        throw new Error("Authentication failed");
    }
    catch (e) {
        throw new Error("Authentication failed");
    }
};
class Strategy extends passport_strategy_1.Strategy {
    name = "cas";
    version;
    ssoBase;
    serverBaseURL;
    validateURI;
    callbackURL;
    _verify;
    constructor(options, verify) {
        super();
        this.version = options.version ?? "CAS1.0";
        this.ssoBase = options.ssoBaseURL;
        this.serverBaseURL = options.serverBaseURL;
        this.callbackURL = options.callbackURL;
        if (!verify) {
            throw new Error("cas authentication strategy requires a verify function");
        }
        this._verify = verify;
        let validateUri;
        switch (this.version) {
            case "CAS1.0":
                validateUri = "/validate";
                break;
            case "CAS2.0":
                validateUri = "/serviceValidate";
            case "CAS3.0":
                validateUri = "/p3/serviceValidate";
                break;
            case "CAS2.0-with-saml":
            case "CAS3.0-with-saml":
                validateUri = "/samlValidate";
                break;
            default:
                const _exhaustiveCheck = this.version;
                throw new Error("unsupported version " + this.version);
        }
        this.validateURI = options.validateURL ?? validateUri;
    }
    authenticate(req, options) {
        options = options ?? {};
        const service = this.service(req);
        const ticket = req.query["ticket"];
        if (!ticket) {
            const redirectURL = url_1.default.parse(this.ssoBase + "/login", true);
            if (options.copyQueryParameters ?? true) {
                // Copy query parameters from original request.
                const originalQuery = url_1.default.parse(req.url, true).query;
                if (originalQuery) {
                    redirectURL.query = originalQuery;
                }
            }
            redirectURL.query.service = service;
            return this.redirect(url_1.default.format(redirectURL));
        }
        let fetchValidation;
        if (this.version === "CAS3.0-with-saml" ||
            this.version === "CAS2.0-with-saml") {
            const requestId = uuid_1.default.v4();
            const issueInstant = new Date().toISOString();
            const soapEnvelope = util_1.default.format('<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="%s" IssueInstant="%s"><samlp:AssertionArtifact>%s</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>', requestId, issueInstant, ticket);
            fetchValidation = axios_1.default.post(`${this.ssoBase}${this.validateURI}`, soapEnvelope, {
                params: {
                    TARGET: service,
                },
                headers: {
                    "Content-Type": "text/xml",
                },
            });
        }
        else {
            fetchValidation = axios_1.default.get(`${this.ssoBase}${this.validateURI}`, {
                params: {
                    ticket: ticket,
                    service: service,
                },
                headers: {
                    "Content-Type": "text/xml",
                },
            });
        }
        fetchValidation
            .then((response) => {
            return response.data;
        })
            .then((xml) => {
            switch (this.version) {
                case "CAS1.0":
                    return validateResponseCas1(xml);
                case "CAS2.0":
                case "CAS3.0":
                    return validateResponseCas3(xml);
                case "CAS2.0-with-saml":
                case "CAS3.0-with-saml":
                    return validateResponseCas3saml(xml);
                default:
                    const _exhaustiveCheck = this.version;
                    throw new Error("unsupported version " + this.version);
            }
        })
            .then((user) => {
            // Call user-provided verify function.
            return this._verify(user, (err, user, info) => {
                // Finish authentication flow.
                if (err) {
                    return this.error(new verror_1.default(err, "user-provided verify function failed"));
                }
                if (!user) {
                    return this.fail(info);
                }
                this.success(user, info);
            });
        })
            .catch((err) => {
            const error = new verror_1.default(err, "Error in validation");
            return this.error(error);
        });
    }
    /**
     * Generate the "service" parameter for the CAS callback URL.
     */
    service(req) {
        let baseUrl;
        if (this.serverBaseURL) {
            baseUrl = this.serverBaseURL;
        }
        else if (req.headers["x-forwarded-host"]) {
            // We need to include this in Express <= v4, since the behavior
            // is to strip the port number by default. This is fixed in Express v5.
            // First, determine host + port.
            let forwardHeader = req.headers["x-forwarded-host"];
            if ((0, underscore_1.isArray)(forwardHeader)) {
                forwardHeader = forwardHeader[0];
            }
            const host = forwardHeader.split(",")[0];
            // Then, determine proto used. We default to http here.
            let forwardProto = req.headers["x-forwarded-proto"];
            if ((0, underscore_1.isArray)(forwardProto)) {
                forwardProto = forwardProto[0];
            }
            const proto = forwardProto ? forwardProto.split(",")[0] : "http";
            baseUrl = `${proto}://${host}`;
        }
        else if (req.headers["host"]) {
            // Fallback to "HOST" header.
            baseUrl = `${req.protocol}://${req.headers["host"]}`;
        }
        else {
            // Final fallback is to req.hostname, generated by Express. As mentioned
            // above, this won't have a port number and so we attempt to use it last.
            baseUrl = `${req.protocol}://${req.hostname}`;
        }
        const serviceURL = this.callbackURL || req.originalUrl;
        const resolvedURL = url_1.default.resolve(baseUrl, serviceURL);
        const parsedURL = url_1.default.parse(resolvedURL, true);
        delete parsedURL.query.ticket;
        parsedURL.search = null;
        return url_1.default.format(parsedURL);
    }
}
exports.Strategy = Strategy;
exports.default = Strategy;
