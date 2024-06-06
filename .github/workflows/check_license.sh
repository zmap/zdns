#!/bin/sh
export NO_HEADERS_FOUND=$(grep -RiL --include="*.go" "ZDNS Copyright .* Regents of the University of Michigan" ./)
if test -n "$NO_HEADERS_FOUND"; then
  echo 'FOUND .go FILES WITHOUT HEADERS.'
  echo "$NO_HEADERS_FOUND"
  exit 1
else
  echo 'All .go files in repo have an appropriate header'
fi