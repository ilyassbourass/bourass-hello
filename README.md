# Bourass Hello - iPhone only

Simple Hello button + BOURASS gold footer. Native SwiftUI.

## 1. Push
```
cd bourass-hello
git init
git add .
git commit -m "Bourass hello v1"
git branch -M main
gh repo create bourass-hello --public --source=. --remote=origin --push
```

## 2. Get IPA
GitHub > Actions > Build iOS > device-build > Artifacts > BourassHello-unsigned-ipa

## 3. Install on iOS 26 (no paid account)
1. Install iTunes + iCloud from Apple site (not Microsoft Store) + Sideloadly
2. USB iPhone, Sideloadly > drag IPA > Apple ID > Start
3. iPhone Settings > General > VPN & Device Management > Trust
4. Refresh every 7 days. Max 3 apps on free ID.
