rule TraceOS_Purple_Canary
{
    meta:
        purpose = "Local detection proof. Matches only the TraceOS canary string."
    strings:
        $canary = "TraceOS-PURPLE-CANARY"
    condition:
        $canary
}
