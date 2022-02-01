import {
    IApplicationContext,
    IPlugin
} from '@znetstar/attic-common/lib/Server';
import { promises as fs } from 'fs';
import {
    IIdentityEntity as
        IIdentityEntityBase
} from "@znetstar/attic-common/lib/IIdentity";

import {
    IAccessToken
} from "@znetstar/attic-common/lib/IAccessToken";

import { GenericError } from '@znetstar/attic-common/lib/Error/GenericError'
import fetch from "node-fetch";
import {IError} from "@znetstar/attic-common/lib/Error/IError";
import {IIdentity} from "@znetstar/attic-common";
import * as URL from 'url';
import * as _ from 'lodash';
import IClient from "@znetstar/attic-common/lib/IClient";

interface IIdentityEntityModel{
    externalId: string;
    otherFields?: any;
}

type IIdentityEntity = IIdentityEntityModel&IIdentityEntityBase&IIdentity;

export class AtticServerInstagram implements IPlugin {
    constructor(public applicationContext: IApplicationContext) {

    }

    public async getInstagramIdentity(accessToken: IAccessToken): Promise<IIdentityEntity> {
        let resp = await fetch(`https://graph.instagram.com/v12.0/me?fields=id,username&access_token=${accessToken.token}`);

        let body:  any;
        let e2: any;
        try { body = await resp.json(); }
        catch (err) { e2 = err; }

        if (resp.status !== 200) {
            throw new GenericError(`Could not locate Instagram identity`, 2001, 403, (
                body || e2
            ) as any as IError);
        }

        // body = body.data;

        let fields: IIdentityEntity = {
            firstName: body.username,
            lastName: '',
            clientName: accessToken.clientName,
            phone: '',
            email: `${body.id}.instagram@${_.get(this, 'applicationContext.config.emailHostname') || process.env.EMAIL_HOSTNAME}`,
            otherFields: body,
            source: {
                href: `https://graph.instagram.com/v12.0/${body.id}`
            },
            type: 'IdentityEntity',
            client: accessToken.client,
            user: null,
            externalId: body.id,
            id: null,
            _id: null
        };

        return fields;
    }


    public async init(): Promise<void> {
        this.applicationContext.registerHook<IIdentityEntity>(`Client.getIdentityEntity.instagram.provider`, this.getInstagramIdentity);
        this.applicationContext.registerHook<string|undefined>('AuthMiddleware.auth.twitter.authorize.getAuthorizeRedirectUri', async (opts: any): Promise<string|undefined> => {
          if (opts.provider.authorizeUri) {
            const u = new URL.URL(opts.provider.authorizeUri);

            u.searchParams.set('scope', opts.provider.scope.join(','));
            return u.href;
          }

        });

        this.applicationContext.registerHook<any>('AuthMiddleware.auth.instagram.authorize.token', async (opts: { provider: any, params: URL.URLSearchParams, fetchOpts: any }): Promise<any> => {
          opts.params.set('redirect_uri', opts.provider.redirectUri);
          opts.fetchOpts = {
            method: 'POST',
            body: opts.params
          }

          return {
            fetchOpts: opts.fetchOpts,
            tokenUri: `https://api.instagram.com/oauth/access_token`
          };
        });
    }

    public get name(): string {
        return JSON.parse((require('fs').readFileSync(require('path').join(__dirname, '..', 'package.json'), 'utf8'))).name;
    }
}

export default AtticServerInstagram;
