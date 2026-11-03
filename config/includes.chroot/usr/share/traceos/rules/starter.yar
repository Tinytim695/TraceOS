rule TraceOS_Text_Marker
{
    meta:
        description = "Starter rule. It matches the words TRACEOS CASE FILE."
    strings:
        $marker = "TRACEOS CASE FILE" ascii
    condition:
        $marker
}
