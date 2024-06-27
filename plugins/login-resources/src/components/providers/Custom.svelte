<script lang="ts">
  import Label from '@hcengineering/ui/src/components/Label.svelte'
  import login from '../../plugin'
  import { getMetadata } from '@hcengineering/platform'

  const name = getMetadata(login.metadata.CustomProviderName)
  const logoUrl = getMetadata(login.metadata.CustomProviderLogoUrl)
</script>

<div class="flex-row-center flex-gap-2">
  {#if logoUrl}
    <img src={logoUrl} class="icon" alt="icon" />
  {/if}
  <Label label={login.string.ContinueWith} params={{ provider: name }} />
</div>

<style lang="scss">
  .icon {
    width: 24px;
    height: 24px;
  }
</style>
