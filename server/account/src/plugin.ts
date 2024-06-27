import { IntlString, Metadata, plugin, Plugin } from '@hcengineering/platform'

/**
 * @public
 */
export const accountId = 'account' as Plugin

/**
 * @public
 */
export const accountPlugin = plugin(accountId, {
  metadata: {
    FrontURL: '' as Metadata<string>,
    SES_URL: '' as Metadata<string>,
    ProductName: '' as Metadata<string>,
    DisableEmailRegistration: '' as Metadata<boolean>
  },
  string: {
    ConfirmationText: '' as IntlString,
    ConfirmationHTML: '' as IntlString,
    ConfirmationSubject: '' as IntlString,
    RecoveryText: '' as IntlString,
    RecoveryHTML: '' as IntlString,
    RecoverySubject: '' as IntlString,
    InviteText: '' as IntlString,
    InviteHTML: '' as IntlString,
    InviteSubject: '' as IntlString
  }
})
