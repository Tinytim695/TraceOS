case "$-" in
  *i*)
    PS1='\[\e[38;5;51m\]TRACEOS\[\e[0m\] \[\e[38;5;141m\]>\[\e[0m\] '
    printf '\n\033[38;5;51mTRACEOS\033[0m  Digital Investigation Workstation\n'
    printf 'Type \033[38;5;51mtraceos status\033[0m or open the Control Centre.\n\n'
    alias trace='traceos'
    alias trace-status='traceos status'
    alias trace-case='traceos case'
    alias trace-tools='traceos tools'
    alias trace-doctor='traceos doctor'
  ;;
esac
