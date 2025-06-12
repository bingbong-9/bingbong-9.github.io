---
icon: fas fa-tags
order: 4
---


### TMUX Config

```sh
# Unbind the default tmux prefix key (Ctrl-B) to avoid conflicts
unbind C-Space

# Set new prefix key to Ctrl-Space
set -g prefix C-Space
bind C-Space send-prefix

# Enable mouse support for selecting and resizing panes
set -g mouse on

# Allow tmux to use the system clipboard
set-option -g set-clipboard on

# Configure copy mode (vi-style keybindings)
# Pressing Enter in copy mode will copy the selected text to the system clipboard
# bind-key -T copy-mode-vi Enter send-keys -X copy-pipe "xclip -selection clipboard -i"

# Enable mouse drag to copy text into the system clipboard
bind -T copy-mode-vi MouseDragEnd1Pane send-keys -X copy-pipe "xclip -selection clipboard -i"

bind-key -T copy-mode-vi Enter send-keys -X copy-pipe "xsel --clipboard --input"
bind -T copy-mode-vi MouseDragEnd1Pane send-keys -X copy-pipe "xsel --clipboard --input"
bind p run-shell "xclip -selection clipboard -o | tmux load-buffer - && tmux paste-buffer"

# VIM copy mode
setw -g mode-keys vi

# Increase the scrollback buffer size to store more history
set-option -g history-limit 10000

# Automatically renumber windows when one is closed
set -g renumber-windows on

# Define key bindings for splitting panes
bind-key "|" split-window -h -c "#{pane_current_path}"  # Split horizontally
bind-key "\\" split-window -fh -c "#{pane_current_path}" # Split horizontally (full width)
bind-key "-" split-window -v -c "#{pane_current_path}"  # Split vertically
bind-key "_" split-window -fv -c "#{pane_current_path}" # Split vertically (full height)

# Move windows left and right
bind -r "<" swap-window -d -t -1
bind -r ">" swap-window -d -t +1

# Create a new window in the same directory as the current pane
bind c new-window -c "#{pane_current_path}"

# Reload tmux configuration file without restarting
bind r source-file ~/.tmux.conf \; display "Reloaded!"

############################
# DESIGN TWEAKS
############################

# Disable notifications when a bell (alert) rings
set -g visual-activity off
set -g visual-bell off
set -g visual-silence off
setw -g monitor-activity off
set -g bell-action none

# Set clock color for clock mode
setw -g clock-mode-colour yellow

# Change copy mode color to green background and black text
setw -g mode-style 'fg=green bg=black'

# Set pane border colors
set -g pane-border-style 'fg=green'
set -g pane-active-border-style 'fg=purple'

############################
# LOGGING & PLUGINS
############################

# Initialize tmux plugin manager
set -g @plugin 'tmux-plugins/tpm'

# Enable session persistence after restart
set -g @plugin 'tmux-plugins/tmux-resurrect'
set -g @plugin 'tmux-plugins/tmux-continuum'
set -g @resurrect-capture-pane-contents 'on'
set -g @continuum-restore 'on'

# Enable logging for tmux sessions
set -g @plugin 'tmux-plugins/tmux-logging'

# Enable better copy/paste integration
set -g @plugin 'tmux-plugins/tmux-yank'

# Automatically start logging on new windows/panes
set-hook -g session-created 'run ~/.bin/tmux_logging.sh'
set-hook -g after-new-window 'run ~/.bin/tmux_logging.sh'
set-hook -g after-split-window 'run ~/.bin/tmux_logging.sh'

# Initialize TMUX plugin manager (must be at the end of the file)
run '~/.tmux/plugins/tpm/tpm'
```



### Terminal colour setup
Inspired from: [Botnetbuddies](https://github.com/botnetbuddies/hackthebox-themes) 

```sh
[:b1dcc9dd-5262-4d8d-a863-c897e6d979b9]
background-color='rgb(0, 10, 20)'
bold-color='rgb(52, 255, 0)'
bold-color-same-as-fg=false
bold-is-bright=true
cursor-background-color='rgb(52, 255, 0)'
cursor-colors-set=true
cursor-foreground-color='rgb(20,29,43)'
foreground-color='rgb(195,195,196)'
highlight-background-color='rgb(0, 16, 82)'
highlight-colors-set=true
highlight-foreground-color='rgb(139, 0, 255)'
palette=['rgb(20,29,43)', 'rgb(255,0,0)', 'rgb(24, 167, 0)', 'rgb(181,124,0)', 'rgb(74, 82, 89)', 'rgb(159,0,255)', 'rgb(41,255,0)', 'rgb(164,177,205)', 'rgb(24,31,43)', 'rgb(158, 0, 0)', 'rgb(43, 239, 0)', 'rgb(255,175,0)', 'rgb(92, 99, 106)', 'rgb(172,35,255)', 'rgb(36,195,36)', 'rgb(181,191,213)']
use-theme-colors=false
visible-name='hackthebox'
```


Apply this within gnome terminal with the following command:
```sh
dconf load /org/gnome/terminal/legacy/profiles:/ < gnome-terminal-profiles.dconf
```



### Cleanup Tmux logs for later reference on a machine
```sh
cat <tmux log source> | sed 's/^[0-9]\{8\}T[0-9]\{6\}-[0-9]\{4\}:[[:space:]]*//'
```
