import { BrandingMap, MeasureContext, concatLink } from '@hcengineering/core'
import { Passport } from '.'
import Router from 'koa-router'
import { Db } from 'mongodb'
import { Strategy as OAuth2Strategy, StrategyOptionsWithRequest, VerifyFunctionWithRequest } from 'passport-oauth2'
import { getBranding, getHost, safeParseAuthState } from './utils'
import axios from 'axios'
import { joinWithProvider, loginWithProvider } from '@hcengineering/account'

class CustomStrategy extends OAuth2Strategy {
  constructor (
    public profileUrl: string,
    options: StrategyOptionsWithRequest,
    verify: VerifyFunctionWithRequest<any, any>
  ) {
    super(options, verify)
  }

  async userProfile (accessToken: string, done: (err?: unknown, profile?: any) => void): Promise<void> {
    try {
      const { data } = await axios.get(this.profileUrl, {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      })

      done(null, data)
    } catch (err) {
      done(err)
    }
  }
}

export function registerCustom (
  measureCtx: MeasureContext,
  passport: Passport,
  router: Router<any, any>,
  accountsUrl: string,
  db: Db,
  productId: string,
  frontUrl: string,
  brandings: BrandingMap
): string | undefined {
  const authorizationURL = process.env.OAUTH2_AUTHORIZATION_URL
  const tokenURL = process.env.OAUTH2_TOKEN_URL
  const clientID = process.env.OAUTH2_CLIENT_ID
  const clientSecret = process.env.OAUTH2_CLIENT_SECRET
  const scope = process.env.OAUTH2_SCOPE ?? ''
  const redirectURL = '/auth/custom/callback'
  const userInfoUrl = process.env.OAUTH2_USER_INFO_URL
  const emailKey = process.env.OAUTH2_EMAIL_KEY ?? 'email'
  const nameKey = process.env.OAUTH2_NAME_KEY ?? 'name'
  // const subjectKey = process.env.OAUTH2_SUBJECT_KEY ?? 'sub'

  if (
    authorizationURL === undefined ||
    tokenURL === undefined ||
    clientID === undefined ||
    clientSecret === undefined ||
    userInfoUrl === undefined
  ) { return }

  passport.use(
    'custom',
    new CustomStrategy(
      userInfoUrl,
      {
        authorizationURL,
        tokenURL,
        clientID,
        clientSecret,
        callbackURL: concatLink(accountsUrl, redirectURL),
        passReqToCallback: true
      },
      (req, accessToken, refreshToken, results, profile, cb) => {
        cb(null, profile)
      }
    )
  )

  router.get('/auth/custom', async (ctx, next) => {
    measureCtx.info('try auth via', { provider: 'custom' })
    const host = getHost(ctx.request.headers)
    const branding = host !== undefined ? brandings[host]?.key ?? undefined : undefined
    const state = encodeURIComponent(
      JSON.stringify({
        inviteId: ctx.query?.inviteId,
        branding
      })
    )

    passport.authenticate('custom', { scope, session: true, state })(ctx, next)
  })

  router.get(
    redirectURL,
    async (ctx, next) => {
      const state = safeParseAuthState(ctx.query?.state)
      measureCtx.info('Auth state', { state })
      const branding = getBranding(brandings, state?.branding)
      measureCtx.info('With branding', { branding })
      const failureRedirect = concatLink(branding?.front ?? frontUrl, '/login')
      measureCtx.info('With failure redirect', { failureRedirect })
      await passport.authenticate('custom', {
        failureRedirect,
        session: true
      })(ctx, next)
    },
    async (ctx, next) => {
      measureCtx.info('Provider auth success', { type: 'custom', user: ctx.state?.user })
      const email = ctx.state.user[emailKey]
      const first = ctx.state.user[nameKey]
      measureCtx.info('Provider auth handler', { email, type: 'custom' })
      if (email !== undefined) {
        try {
          const state = safeParseAuthState(ctx.query?.state)
          const branding = getBranding(brandings, state?.branding)
          if (state.inviteId != null && state.inviteId !== '') {
            const loginInfo = await joinWithProvider(
              measureCtx,
              db,
              productId,
              null,
              email,
              first,
              '',
              state.inviteId as any
            )
            if (ctx.session != null) {
              ctx.session.loginInfo = loginInfo
            }
          } else {
            const loginInfo = await loginWithProvider(measureCtx, db, productId, null, email, first, '')
            if (ctx.session != null) {
              ctx.session.loginInfo = loginInfo
            }
          }

          // Successful authentication, redirect to your application
          measureCtx.info('Success auth, redirect', { email, type: 'custom' })
          ctx.redirect(concatLink(branding?.front ?? frontUrl, '/login/auth'))
        } catch (err: any) {
          measureCtx.error('failed to auth', { err, type: 'custom', user: ctx.state?.user })
        }
      }
      await next()
    }
  )

  return 'custom'
}
