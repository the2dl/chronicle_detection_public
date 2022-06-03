rule potentially_malicious_iso_payload_via_rundll32_lnk {
  meta:
    author = "Dan Lussier"
    description = "Identify rundll32 launching a malicious DLL file from .lnk files sourcing from mounted disks outside of C"
    version = "1.1"
    severity = "High"
    mitre_TA = "TA0002"
    mitre_T1 = "T1204.001"
    mitre_url = "https://attack.mitre.org/techniques/T1204/001/"
    reference_docs = "https://thedfirreport.com/2022/04/25/quantum-ransomware/"
    false_positives = "There could be rare cases with files run from other mounted disks kick off rundll32 with an LNK, tune accordingly."

  events:
        $e1.principal.platform = "WINDOWS"
          // Look for rundll launching
        $e1.target.process.file.full_path = /.*\\windows\\system32\\rundll32\.exe/ nocase
          // Ignore anything that is coming from C as the mount point fro a malicious ISO will be a different drive letter
        $e1.target.resource.attribute.labels.value != /c\:\\.*/ nocase
          // Match this back to the "LinkName" attribute from your EDR vendor, this may change depending on what you use
        $e1.target.resource.attribute.labels.key = "LinkName"
        $e1.principal.asset.hostname = $hostname

  match:
        $hostname over 1m

  condition:
    $e1
}