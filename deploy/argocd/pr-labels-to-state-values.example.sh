#!/bin/sh
#
# For the Argo CD plugin that renders deploy/helmfile/preview: the block to paste in its
# script, before the helmfile command, which then ends with `$PR_LABEL_OPTIONS`. It turns
# the labels of a pull request into the options that pick the product images under test:
#
#   docs:pr-2694         ->  --state-values-set docsImageTag=pr-2694
#   drive:encryption     ->  --state-values-set driveImageTag=encryption
#   accounts:encryption  ->  --state-values-set accountsImageTag=encryption
#   grist:1.5.0          ->  --state-values-set gristImageTag=1.5.0
#   <product>:<namespace>/*:<tag>
#                        ->  --state-values-set <product>ImageNamespace=<namespace>
#                            --state-values-set <product>ImageTag=<tag>
#   grist:<repository>:<tag>
#                        ->  --state-values-set gristImageRepository=<repository>
#                            --state-values-set gristImageTag=<tag>
#
# A product's images may come from elsewhere than its default repositories (a fork's
# account on Docker Hub, or any registry: another forge's, a self-hosted one), for a
# branch no CI of the suite builds. The label's last `:` separates the tag (a tag never
# holds one); what comes before it says where the images are:
#
#   - nothing: the default repositories;
#   - `<namespace>/*`: every image of the product under that namespace, the `*` standing
#     for each image's usual name, the last part of its default repository
#     (`impress-backend`, `drive-frontend`, `grist-oss`...): one label covers the several
#     images of a product;
#   - a repository without `*`: that very repository, for Grist alone, whose one image
#     may then have any name (Docs, Drive and Accounts have several images: refused).
#
# A namespace or a repository is `[registry[:port]/]path`; the registry is told apart as
# Docker and Kubernetes do it, by a first part holding a `.` or a `:` (or being
# `localhost`), Docker Hub otherwise. A `:` is only a registry's port (digits), and a
# repository naming a registry goes on with a path. Images are named by tag only, never
# by digest (`@sha256:...`). GitHub caps a label at 50 characters, the product prefix
# included.
#
# The ApplicationSet (applicationset-preview.example.yaml) passes the labels as they are,
# comma-separated, in PR_LABELS, which a sidecar plugin sees as ARGOCD_ENV_PR_LABELS. Other
# labels are ignored, and a product without a label runs the helmfile's default. With two
# labels for one product the last wins, each being its own option.
#
# Plain POSIX sh: plugins run their script with `sh -c`, and on Debian-based images `sh`
# is dash, which has no here-string (`<<<`), arrays, `[[ ]]` or `printf %q`.
#
# A label is anyone's to set on a pull request, and the helmfile command is a string the
# script evals: a label is kept only when its tag is a valid image tag (letters, digits,
# `.`, `_`, `-`) and its namespace or repository a valid one (lowercase letters, digits,
# `.`, `_`, `-`, `/` and a registry's `:`), characters that mean nothing to the shell. The
# `*` never reaches the eval (where it would expand to file names): only the namespace
# before it is passed on.
#
# Run it to see what a list of labels gives:
#
#   ARGOCD_ENV_PR_LABELS='preview,docs:pr-2694,drive:encryption' ./pr-labels-to-state-values.example.sh

# Pull request labels "app:[where:]tag" -> state values "<app>ImageNamespace=<namespace>"
# or "gristImageRepository=<repository>", and "<app>ImageTag=<tag>"
PR_LABEL_OPTIONS=""
set -f # no filename expansion on a label like "docs:*"
OLD_IFS=$IFS
IFS=','
for label in ${ARGOCD_ENV_PR_LABELS:-}; do
  case "$label" in
    docs:* | drive:* | accounts:* | grist:*)
      app="${label%%:*}"
      value="${label#*:}"
      tag="${value##*:}"
      where=""
      case "$value" in *:*) where="${value%:*}" ;; esac
      # Set on GitHub by anyone and passed to eval: only a valid image tag is accepted
      case "$tag" in
        '' | [!A-Za-z0-9_]* | *[!A-Za-z0-9._-]*) valid="" ;;
        *) valid=yes ;;
      esac
      [ ${#tag} -le 128 ] || valid=""
      # Where the images are: `<namespace>/*`, or a repository (Grist alone)
      option=""
      reason="not [<namespace>/*:]<tag>"
      case "$where" in
        '') ;;
        */\*)
          repository="${where%/\*}"
          option="${app}ImageNamespace"
          ;;
        *\*) valid="" ;;
        *)
          repository="$where"
          option="${app}ImageRepository"
          if [ "$app" != grist ]; then
            valid=""
            reason="several images: name a namespace, <namespace>/*:<tag>"
          fi
          ;;
      esac
      # And a valid namespace or repository: lowercase parts joined by `/`, a registry's
      # port included
      if [ -n "$option" ]; then
        case "$repository" in
          '' | [!a-z0-9]* | *[!a-z0-9]) valid="" ;;
          *[!a-z0-9._/:-]* | *//* | */[!a-z0-9]* | *[!a-z0-9]/*) valid="" ;;
        esac
        # A `:` only in the first part, before a registry's port (digits); and a registry
        # is followed by a path: a repository naming one alone is no image
        first="${repository%%/*}"
        case "${repository#"$first"}" in *:*) valid="" ;; esac
        case "$first" in
          *:*)
            case "${first#*:}" in '' | *[!0-9]*) valid="" ;; esac
            case "$first" in *[!a-z0-9]:*) valid="" ;; esac
            ;;
        esac
        case "$first" in
          *.* | *:* | localhost)
            [ "$option" = "${app}ImageRepository" ] && [ "$first" = "$repository" ] && valid=""
            ;;
        esac
      fi
      if [ -n "$valid" ]; then
        if [ -n "$option" ]; then
          PR_LABEL_OPTIONS="$PR_LABEL_OPTIONS --state-values-set ${option}=${repository}"
        fi
        PR_LABEL_OPTIONS="$PR_LABEL_OPTIONS --state-values-set ${app}ImageTag=${tag}"
      else
        echo "pull request label ignored ($reason): $label" >&2
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
