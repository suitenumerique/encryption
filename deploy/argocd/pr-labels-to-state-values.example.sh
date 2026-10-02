#!/bin/sh
#
# For the Argo CD plugin that renders deploy/helmfile/preview: the block to paste in its
# script, before the helmfile command, which then ends with `$PR_LABEL_OPTIONS`. It turns
# the labels of a pull request into the options that pick the product images under test:
#
#   docs:pr-2694      ->  --state-values-set docsImageTag=pr-2694
#   drive:encryption  ->  --state-values-set driveImageTag=encryption
#
# The ApplicationSet (applicationset-preview.example.yaml) passes the labels as they are,
# comma-separated, in PR_LABELS, which a sidecar plugin sees as ARGOCD_ENV_PR_LABELS. Other
# labels are ignored, and a product without a label runs the helmfile's default, `main`.
# With two labels for one product the last wins, each being its own option.
#
# Plain POSIX sh: plugins run their script with `sh -c`, and on Debian-based images `sh`
# is dash, which has no here-string (`<<<`), arrays, `[[ ]]` or `printf %q`.
#
# A label is anyone's to set on a pull request, and the helmfile command is a string the
# script evals: a tag is kept only when it is a valid image tag, whose characters
# (letters, digits, `.`, `_`, `-`) mean nothing to the shell.
#
# Run it to see what a list of labels gives:
#
#   ARGOCD_ENV_PR_LABELS='preview,docs:pr-2694,drive:encryption' ./pr-labels-to-state-values.example.sh

# Pull request labels "app:tag" -> state value "<app>ImageTag=<tag>"
PR_LABEL_OPTIONS=""
set -f # no filename expansion on a label like "docs:*"
OLD_IFS=$IFS
IFS=','
for label in ${ARGOCD_ENV_PR_LABELS:-}; do
  case "$label" in
    docs:* | drive:*)
      app="${label%%:*}"
      tag="${label#*:}"
      # Set on GitHub by anyone and passed to eval: only a valid image tag is accepted
      case "$tag" in
        '' | [!A-Za-z0-9_]* | *[!A-Za-z0-9._-]*) valid="" ;;
        *) valid=yes ;;
      esac
      [ ${#tag} -le 128 ] || valid=""
      if [ -n "$valid" ]; then
        PR_LABEL_OPTIONS="$PR_LABEL_OPTIONS --state-values-set ${app}ImageTag=${tag}"
      else
        echo "pull request label ignored (not an image tag): $label" >&2
      fi
      ;;
  esac
done
IFS=$OLD_IFS
set +f

# Run as a command rather than pasted or sourced: show the result.
case $0 in
  *pr-labels-to-state-values.example.sh) echo "$PR_LABEL_OPTIONS" ;;
esac
