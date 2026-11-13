# Firebase Console settings required for the new reset flow

Two one-time settings (they cannot be changed from code):

1. **Password-reset email → your own page**
   Firebase Console → Authentication → Templates → *Password reset* → ✏️ → **Customize action URL** →
   `https://YOUR-DOMAIN/reset-password`
   (also make sure YOUR-DOMAIN is listed under Authentication → Settings → *Authorized domains*).
   The link in the email then opens the in-app `/reset-password` page instead of the Firebase-hosted page.

2. **"Account doesn't exist" error for deleted accounts**
   Firebase Console → Authentication → Settings → *User actions* → turn **Email enumeration protection OFF**.
   While it is ON, Firebase pretends every email exists and the app cannot tell a deleted account apart.
   Trade-off: anyone can then test whether an email is registered. Keep it ON if that matters more to you.
