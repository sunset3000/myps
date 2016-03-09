$srvName = "adfs.tfha7.local"
$srvCertThumbPrint = "1C1AB9FA79B984F449313246E1730B3E4C72066B"
$srvAccount = "adfs"
$subdomain = "t2cpsm"

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path 

function installADFSFarm
{
    param(
        [Parameter(Position=0,Mandatory=$true)][string] $ServiceName,
        [Parameter(Position=1,Mandatory=$true)][string] $SrvCommCertThumbPrint,
        [Parameter(Position=2,Mandatory=$false)][string] $ServiceAccount="adfs"
    )
    Import-Module ServerManager
    Add-WindowsFeature ADFS-Federation

    # import KDS root key
    # In order to support the creation of these new group MSAs, we will need to add a new KDS “root key.” 
    Add-KdsRootKey –EffectiveTime ((get-date).addhours(-10))

    Import-Module ADFS
    Install-AdfsFarm `
    -CertificateThumbprint:$SrvCommCertThumbPrint `
    -FederationServiceDisplayName:"ADFS for ShareFile" `
    -FederationServiceName:$ServiceName `
    -GroupServiceAccountIdentifier:("{0}\{1}`$" -f $env:USERDOMAIN, $ServiceAccount)
}

function addShareFileTrust 
{
    param(
        [Parameter(Position=0,Mandatory=$true)][string] $SubDomain,
        [Parameter(Position=1,Mandatory=$false)][string] $IssuanceTransformRulesFile = (Join-Path ($scriptPath) "sf_claimrules.txt"),
        [Parameter(Position=2,Mandatory=$false)][string] $IssuanceAuthorizationRulesFile = (Join-Path ($scriptPath) "sf_iarules.txt")
    )
    Import-Module ADFS

    $ep = New-ADFSSamlEndpoint -Binding "POST" -Protocol "SAMLAssertionConsumer" -Uri ("https://{0}.sharefile.com/saml/acs" -f $SubDomain)
    $RPTId = ("https://{0}.sharefile.com/saml/info" -f $SubDomain)
    Add-AdfsRelyingPartyTrust -Identifier @($RPTId) -Name "RTL for ShareFile" -ClaimsProviderName @("Active Directory") -Enabled $true `
        -EncryptClaims $true -IssuanceTransformRulesFile $IssuanceTransformRulesFile  -IssuanceAuthorizationRulesFile $IssuanceAuthorizationRulesFile `
        -ProtocolProfile 'WsFed-SAML' -SignatureAlgorithm 'http://www.w3.org/2000/09/xmldsig#rsa-sha1' -SamlEndpoint $ep

}

installADFSFarm -ServiceName $srvName -SrvCommCertThumbPrint $srvCertThumbPrint
addShareFileTrust -SubDomain $subdomain