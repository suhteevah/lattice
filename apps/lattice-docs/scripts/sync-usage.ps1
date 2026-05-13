# sync-usage.ps1
#
# Mirror ../../docs/usage/*.md into src/content/docs/docs/usage/ so
# Starlight's content collection can index the canonical docs without
# requiring symlinks (which are unreliable on Windows + MinGW dev hosts
# and break Vercel's build container on case-sensitive paths).
#
# Idempotent: re-running with no changes is a no-op. The destination is
# git-ignored so this is a build-time artifact, not source.
#
# Invoked by `npm run predev` and `npm run prebuild`. Can also be run
# manually: `npm run sync-usage`.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$appRoot = Split-Path -Parent $here
$repoRoot = Resolve-Path (Join-Path $appRoot '..\..')

$sourceDir = Join-Path $repoRoot 'docs\usage'
$destDir = Join-Path $appRoot 'src\content\docs\docs\usage'

Write-Host "[sync-usage] source: $sourceDir"
Write-Host "[sync-usage] dest:   $destDir"

if (-not (Test-Path $sourceDir)) {
    Write-Warning "[sync-usage] source directory does not exist yet: $sourceDir"
    Write-Warning "[sync-usage] creating empty dest tree with a placeholder so Starlight can still build."

    New-Item -ItemType Directory -Force -Path $destDir | Out-Null

    $placeholder = @"
---
title: Documentation pending
description: The Lattice usage docs are still being written.
---

The usage documentation is being authored at `docs/usage/` in the repo
root and will appear here on the next site build. Check back shortly.

In the meantime, the source of truth for everything technical lives in:

- [README](https://github.com/suhteevah/lattice/blob/main/README.md)
- [HANDOFF](https://github.com/suhteevah/lattice/blob/main/docs/HANDOFF.md)
- [ARCHITECTURE](https://github.com/suhteevah/lattice/blob/main/docs/ARCHITECTURE.md)
- [THREAT MODEL](https://github.com/suhteevah/lattice/blob/main/docs/THREAT_MODEL.md)
- [ROADMAP](https://github.com/suhteevah/lattice/blob/main/docs/ROADMAP.md)
"@

    $placeholder | Out-File -FilePath (Join-Path $destDir 'index.md') -Encoding utf8 -Force
    Write-Host "[sync-usage] placeholder index.md written. exiting 0."
    exit 0
}

# Wipe and rebuild the mirror so deletions in source propagate.
if (Test-Path $destDir) {
    Remove-Item -Recurse -Force $destDir
}
New-Item -ItemType Directory -Force -Path $destDir | Out-Null

function Convert-ToTitle {
    param([string]$slug)
    # "self-hosting" -> "Self-hosting" (sentence case, dashes -> spaces)
    if ([string]::IsNullOrWhiteSpace($slug)) { return 'Untitled' }
    $words = $slug -split '[-_]'
    if ($words.Count -eq 0) { return 'Untitled' }
    $first = $words[0]
    if ($first.Length -gt 1) {
        $first = $first.Substring(0, 1).ToUpper() + $first.Substring(1).ToLower()
    } else {
        $first = $first.ToUpper()
    }
    $rest = @()
    foreach ($w in $words[1..($words.Count - 1)]) { $rest += $w.ToLower() }
    return (@($first) + $rest) -join ' '
}

function Copy-WithFrontmatter {
    param(
        [string]$Source,
        [string]$Destination
    )

    $raw = Get-Content -LiteralPath $Source -Raw -Encoding UTF8
    if ($null -eq $raw) { $raw = '' }

    $hasFrontmatter = $raw -match '^\s*---\s*\r?\n'
    $hasTitle = $false
    if ($hasFrontmatter) {
        # crude but sufficient: look for a `title:` key inside the first ---...--- block
        $match = [regex]::Match($raw, '(?s)^\s*---\s*\r?\n(.*?)\r?\n---\s*\r?\n')
        if ($match.Success) {
            $block = $match.Groups[1].Value
            if ($block -match '(?m)^\s*title\s*:') {
                $hasTitle = $true
            }
        }
    }

    if (-not $hasTitle) {
        # derive a title — prefer the first H1, fall back to the filename slug
        $title = $null
        $h1 = [regex]::Match($raw, '(?m)^\s*#\s+(.+?)\s*$')
        if ($h1.Success) {
            $title = $h1.Groups[1].Value.Trim()
        }
        if (-not $title) {
            $slug = [System.IO.Path]::GetFileNameWithoutExtension($Source)
            if ($slug -eq 'index') {
                $parent = Split-Path -Parent $Source
                $slug = Split-Path -Leaf $parent
                if ($slug -eq 'usage') { $slug = 'Documentation' }
            }
            $title = Convert-ToTitle -slug $slug
        }

        # Escape any double-quotes in the derived title.
        $safeTitle = $title -replace '"', '\"'
        $inject = "---`r`ntitle: `"$safeTitle`"`r`n---`r`n`r`n"

        if ($hasFrontmatter) {
            # source has frontmatter but lacks a title — splice title into the existing block
            $raw = [regex]::Replace(
                $raw,
                '(?s)^\s*---\s*\r?\n',
                "---`r`ntitle: `"$safeTitle`"`r`n",
                1
            )
        } else {
            $raw = $inject + $raw
        }
    }

    # Ensure parent dir exists and write.
    $destParent = Split-Path -Parent $Destination
    if (-not (Test-Path $destParent)) {
        New-Item -ItemType Directory -Force -Path $destParent | Out-Null
    }
    [System.IO.File]::WriteAllText($Destination, $raw, [System.Text.UTF8Encoding]::new($false))
}

$copied = 0
Get-ChildItem -Path $sourceDir -Recurse -File -Include '*.md', '*.mdx' | ForEach-Object {
    $rel = $_.FullName.Substring($sourceDir.Length).TrimStart('\', '/')
    $target = Join-Path $destDir $rel
    Copy-WithFrontmatter -Source $_.FullName -Destination $target
    $copied++
}

Write-Host "[sync-usage] mirrored $copied file(s) into src/content/docs/docs/usage/ (frontmatter normalized)"
