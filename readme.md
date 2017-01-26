# WolfeReiter OWIN Security Provider for AzureAD

## Setup

1. Web.config ClaimsAuthenticationManager

Register the custom `ClaimsAuthenticationManager` type to replace the generic one. This is what maps Groups to Roles.

```xml
<configuration>
  <configSections>
    <section name="system.identityModel" type="System.IdentityModel.Configuration.SystemIdentityModelSection, System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=B77A5C561934E089" />
  </configSections>
 ...
  <system.identityModel>
    <identityConfiguration>
      <claimsAuthenticationManager type="WolfeReiter.Owin.AzureAD.Owin.Security.AzureGraphClaimsAuthenticationManager, WolfeReiter.Owin.AzureAD" />
    </identityConfiguration>
  </system.identityModel>
</configuration>
```

2. Gobal.asax.cs::Application_PostAuthenticateRequest()

Create a PostAuthenticationRequest event handler method in Global.asax.cs and call `AzureAuthStartup.PostAuthenticateRequest()`. This is what ensures that the Group to Role mapping happens.

3. OWIN Startup handler `Startup.cs`

Call `AzureAuthStartup.ConfigureAuth(app)` in the `Configuration(IAppBuilder)` method. This is what registers AzureAD as the authentication provider.

4. Web.config appSettings

```xml
  <appSettings>
    <add key="azure:clientId" value="client-id-registered-in-azure" />
    <add key="azure:appKey" value="key-registered-in-azure" />
    <add key="azure:tenant" value="azure-tenant-name" />
    <add key="azure:instancePattern" value="https://login.microsoftonline.com/{0}" />
    <add key="azure:postLogoutRedirectUri" value="https://localhost:44300/" />
    <add key="azure:graphUrl" value="https://graph.windows.net" />
    <add key="azure:graphApiVersion" value="1.5" />
    <!-- view to format error message string returned from Azure -->
    <add key="azure:authFailedUrlTemplate" value= "/Error/ShowError?signIn=true&errorMessage={0}">
  </appSettings>
  ```