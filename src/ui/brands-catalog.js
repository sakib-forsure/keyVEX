// Offline brand marks (inline SVG glyphs) and the service presets. Reused from the original KeyVEX file.
export const SERVICES = [
  { name:"Facebook",    web:"www.facebook.com",    cat:"Social" },
  { name:"Google",      web:"accounts.google.com", cat:"Email" },
  { name:"Gmail",       web:"mail.google.com",     cat:"Email" },
  { name:"Instagram",   web:"www.instagram.com",   cat:"Social" },
  { name:"WhatsApp",    web:"web.whatsapp.com",    cat:"Social" },
  { name:"LinkedIn",    web:"www.linkedin.com",    cat:"Social" },
  { name:"Netflix",     web:"www.netflix.com",     cat:"Entertainment" },
  { name:"YouTube",     web:"www.youtube.com",     cat:"Entertainment" },
  { name:"Spotify",     web:"open.spotify.com",    cat:"Entertainment" },
  { name:"X (Twitter)", web:"x.com",               cat:"Social" },
  { name:"Telegram",    web:"web.telegram.org",    cat:"Social" },
  { name:"Discord",     web:"discord.com",         cat:"Social" },
  { name:"TikTok",      web:"www.tiktok.com",      cat:"Social" },
  { name:"GitHub",      web:"github.com",          cat:"Work" },
  { name:"Amazon",      web:"www.amazon.com",      cat:"Shopping" },
  { name:"Apple",       web:"appleid.apple.com",   cat:"Other" },
  { name:"Microsoft",   web:"account.microsoft.com", cat:"Work" },
  { name:"Proton VPN",  web:"account.proton.me",   cat:"Other" },
  { name:"Dribbble",    web:"dribbble.com",        cat:"Work" },
  { name:"PayPal",      web:"www.paypal.com",      cat:"Banking" }
];
/* Brand marks: inline SVG glyphs in brand colours */
export const BRAND_SVG = {
  "facebook":{ bg:"#1877F2", svg:'<path fill="#fff" d="M13.5 21v-7h2.4l.4-3h-2.8V9.1c0-.9.3-1.5 1.6-1.5h1.3V4.9c-.3 0-1.1-.1-2.1-.1-2.1 0-3.6 1.3-3.6 3.7V11H8.3v3h2.4v7h2.8z"/>' },
  "instagram":{ bg:"linear-gradient(45deg,#FEDA75,#FA7E1E,#D62976,#962FBF)", svg:'<g fill="none" stroke="#fff" stroke-width="1.8"><rect x="5" y="5" width="14" height="14" rx="4"/><circle cx="12" cy="12" r="3.4"/><circle cx="17.2" cy="6.8" r="1" fill="#fff" stroke="none"/></g>' },
  "whatsapp":{ bg:"#25D366", svg:'<path fill="#fff" d="M12 4a8 8 0 0 0-6.9 12L4 20l4.1-1.1A8 8 0 1 0 12 4zm4.4 11.4c-.2.6-1.2 1.1-1.7 1.2-.4 0-1 .2-3.3-.7-2.8-1.1-4.6-4-4.7-4.2-.1-.2-1.1-1.5-1.1-2.9s.7-2 1-2.3c.2-.3.5-.3.7-.3h.5c.2 0 .4 0 .6.5l.9 2.1c.1.2.1.4 0 .6l-.4.6-.4.5c-.1.1-.3.3-.1.6.2.3.8 1.3 1.7 2.1 1.2 1.1 2.2 1.4 2.5 1.6.3.1.5.1.7-.1l1-1.2c.2-.3.4-.2.7-.1l2.1 1c.3.2.5.3.6.4 0 .1 0 .7-.2 1.1z"/>' },
  "linkedin":{ bg:"#0A66C2", svg:'<path fill="#fff" d="M6.9 8.6H4.2V20h2.7V8.6zM5.5 7.3a1.6 1.6 0 1 0 0-3.2 1.6 1.6 0 0 0 0 3.2zM20 13.4c0-3-1.6-4.9-4.2-4.9-1.6 0-2.5.8-3 1.6V8.6H10V20h2.8v-5.9c0-1.3.6-2.1 1.8-2.1 1.1 0 1.7.7 1.7 2.1V20H20v-6.6z"/>' },
  "x (twitter)":{ bg:"#000000", svg:'<path fill="#fff" d="M17.8 4h2.7l-6 6.8L21.5 20h-5.5l-4.3-5.6L6.7 20H4l6.4-7.3L3.7 4H9.3l3.9 5.1L17.8 4zm-1 14.4h1.5L8.6 5.5H7L16.8 18.4z"/>' },
  "x":{ bg:"#000000", svg:'<path fill="#fff" d="M17.8 4h2.7l-6 6.8L21.5 20h-5.5l-4.3-5.6L6.7 20H4l6.4-7.3L3.7 4H9.3l3.9 5.1L17.8 4zm-1 14.4h1.5L8.6 5.5H7L16.8 18.4z"/>' },
  "twitter":{ bg:"#000000", svg:'<path fill="#fff" d="M17.8 4h2.7l-6 6.8L21.5 20h-5.5l-4.3-5.6L6.7 20H4l6.4-7.3L3.7 4H9.3l3.9 5.1L17.8 4zm-1 14.4h1.5L8.6 5.5H7L16.8 18.4z"/>' },
  "youtube":{ bg:"#FF0000", svg:'<path fill="#fff" d="M21.6 8.2a2.5 2.5 0 0 0-1.8-1.8C18.2 6 12 6 12 6s-6.2 0-7.8.4A2.5 2.5 0 0 0 2.4 8.2 26 26 0 0 0 2 12a26 26 0 0 0 .4 3.8 2.5 2.5 0 0 0 1.8 1.8c1.6.4 7.8.4 7.8.4s6.2 0 7.8-.4a2.5 2.5 0 0 0 1.8-1.8A26 26 0 0 0 22 12a26 26 0 0 0-.4-3.8zM10 15.2V8.8l5.2 3.2L10 15.2z"/>' },
  "spotify":{ bg:"#1DB954", svg:'<g fill="none" stroke="#fff" stroke-width="1.7" stroke-linecap="round"><path d="M6.5 9.6a10 10 0 0 1 11 .8M7 12.4a7.6 7.6 0 0 1 8.4.6M7.5 15a5.4 5.4 0 0 1 6 .5"/></g>' },
  "telegram":{ bg:"#229ED9", svg:'<path fill="#fff" d="M20.7 4.6 3.9 11.1c-.9.35-.86 1.66.05 1.97l4.2 1.4 1.63 5.1c.3.93 1.44 1.14 2.05.38l2.35-2.9 4.45 3.27c.8.59 1.95.13 2.12-.84l1.7-12.7c.14-1.03-.9-1.8-1.75-1.18zM8.9 13.9l9.7-6.1c.25-.16.5.22.27.4l-8.2 7.4-.35 3.5L8.9 13.9z"/>' },
  "discord":{ bg:"#5865F2", svg:'<path fill="#fff" d="M18.6 6.2A16 16 0 0 0 14.6 5l-.2.4a13 13 0 0 1 3.7 1.9 12.4 12.4 0 0 0-11.9 0A13 13 0 0 1 9.9 5.4L9.7 5a16 16 0 0 0-4 1.2C3.1 10.1 2.4 13.9 2.7 17.7a16 16 0 0 0 4.9 2.5l.4-.6a10 10 0 0 1-1.6-.8l.4-.3a14 14 0 0 0 10.7 0l.4.3c-.5.3-1 .6-1.6.8l.4.6a16 16 0 0 0 4.9-2.5c.4-4.4-.7-8.2-3-11.5zM8.7 15.3c-1 0-1.7-.9-1.7-2s.7-2 1.7-2 1.8.9 1.7 2c0 1.1-.7 2-1.7 2zm6.6 0c-1 0-1.7-.9-1.7-2s.7-2 1.7-2 1.8.9 1.7 2c0 1.1-.7 2-1.7 2z"/>' },
  "tiktok":{ bg:"#000000", svg:'<path fill="#fff" d="M16.6 4c.4 2 1.8 3.5 3.9 3.8v3c-1.5 0-2.9-.5-3.9-1.3v6.3c0 3.4-2.4 5.2-5.1 5.2A5.1 5.1 0 0 1 6.4 16a5.1 5.1 0 0 1 5.4-5v3.1c-1-.3-2.1.4-2.1 1.6 0 .9.7 1.6 1.6 1.6 1 0 1.8-.8 1.8-2V4h3.5z"/>' },
  "github":{ bg:"#171515", svg:'<path fill="#fff" d="M12 4a8 8 0 0 0-2.5 15.6c.4.1.6-.2.6-.4v-1.4c-2.5.6-3-1.2-3-1.2-.4-1-1-1.3-1-1.3-.8-.6.1-.6.1-.6.9.1 1.4.9 1.4.9.8 1.4 2.1 1 2.6.7.1-.6.3-1 .6-1.2-2-.2-4.1-1-4.1-4.4 0-1 .3-1.8.9-2.4-.1-.2-.4-1.1.1-2.3 0 0 .7-.2 2.4.9a8.3 8.3 0 0 1 4.4 0c1.7-1.1 2.4-.9 2.4-.9.5 1.2.2 2.1.1 2.3.6.6.9 1.4.9 2.4 0 3.4-2.1 4.2-4.1 4.4.3.3.6.8.6 1.7v2.5c0 .2.2.5.6.4A8 8 0 0 0 12 4z"/>' },
  "netflix":{ bg:"#000000", svg:'<path fill="#E50914" d="M7 4h3.2l3.6 9.6V4H17v16h-3.2l-3.6-9.7V20H7V4z"/>' },
  "google":{ bg:"#FFFFFF", svg:'<path fill="#4285F4" d="M21.6 12.2c0-.7-.1-1.4-.2-2H12v3.9h5.4a4.6 4.6 0 0 1-2 3v2.5h3.2c1.9-1.7 3-4.3 3-7.4z"/><path fill="#34A853" d="M12 22c2.7 0 5-.9 6.6-2.4l-3.2-2.5c-.9.6-2 1-3.4 1-2.6 0-4.8-1.8-5.6-4.2H3.1v2.6A10 10 0 0 0 12 22z"/><path fill="#FBBC05" d="M6.4 13.9a6 6 0 0 1 0-3.8V7.5H3.1a10 10 0 0 0 0 9l3.3-2.6z"/><path fill="#EA4335" d="M12 5.9c1.5 0 2.8.5 3.8 1.5L18.7 4.5A10 10 0 0 0 3.1 7.5l3.3 2.6C7.2 7.7 9.4 5.9 12 5.9z"/>' },
  "gmail":{ bg:"#FFFFFF", svg:'<path fill="#EA4335" d="M4 6.5v11h3V11l5 3.7L17 11v6.5h3v-11l-8 6-8-6z"/>' },
  "dribbble":{ bg:"#EA4C89", svg:'<g fill="none" stroke="#fff" stroke-width="1.5"><circle cx="12" cy="12" r="8"/><path d="M6 7.5c3 2.6 6.4 3.4 10.3 2.6M18.5 9a13 13 0 0 1-4 7.6M8 18.6c1.2-3.4 4-5.4 8-5.6"/></g>' },
  "proton vpn":{ bg:"#6D4AFF", svg:'<path fill="#fff" d="M5 19V5.8A.8.8 0 0 1 5.8 5h5.1c3 0 5 1.9 5 4.5S13.9 14 10.9 14H8v5H5zm3-7.7h2.8c1.3 0 2.1-.7 2.1-1.8s-.8-1.8-2.1-1.8H8v3.6zM16.5 19l2.7-8h3l-4.2 8h-1.5z"/>' },
  "amazon":{ bg:"#FF9900", svg:'<path fill="#221F1F" d="M7.5 15.6c2.9 2.1 6.8 2.1 9.9-.5.5-.4-.2-1-1.1-.4-1.7.7-4.7.8-7-.2-.7-.3-1.4.3-.8.7zM16.4 13.7c-.4-.5-2.1-.3-3 .1-.3.1 0 .6.3.5 1.2-.3 3.1-.2 2.6.3-.5 1.2-1.2 2.4.1 1.8 1.3-.6 1.7-2.2 1-2.7zM14.8 10.6c0 .8.1 1.5-.8 2.1-.7.5-1.6.3-2.2-.1-.7-.4-1.1-1.2-1-2 .1-1.6 1.8-2.4 4-1.9v.5c0 .6 0 1-.2 1.4zm.1-5.4h-5.6v1.6h4v.1c-.6.7-1.6 1.8-1.7 2.7h2c.2-.8 1-1.7 1.5-2.4l1.4-1.8v-1z" transform="translate(0,1) scale(.92)"/>' },
  "apple":{ bg:"#000000", svg:'<path fill="#fff" d="M15.9 12.7c0-2.4 2-3.6 2.1-3.7-1.1-1.7-2.9-1.9-3.5-1.9-1.5-.2-2.9.9-3.7.9-.8 0-1.9-.9-3.2-.9-1.6 0-3.1 1-4 2.4-1.7 2.9-.4 7.3 1.2 9.7.8 1.2 1.8 2.5 3 2.4 1.2 0 1.6-.7 3-.7s1.8.7 3 .7c1.3 0 2.1-1.2 2.9-2.3.9-1.3 1.3-2.6 1.3-2.7-.1 0-2.7-1-2.9-3.9zM13.7 5.6c.7-.8 1.1-1.9 1-3-1 0-2.1.6-2.8 1.4-.6.7-1.2 1.9-1 3 1.1.1 2.1-.6 2.8-1.4z"/>' },
  "paypal":{ bg:"#003087", svg:'<path fill="#fff" d="M8 19.5 9.6 5h5.2c2.5 0 4 1.5 3.9 3.9-.2 2.8-2.1 4.4-5 4.4H11l-.6 4h-2.2c-.3 0-.5-.3-.4-.6L8 19.5zM11.6 7.3l-.5 3.7h2.3c1.3 0 2.1-.7 2.2-1.9.1-1.1-.6-1.8-1.8-1.8h-2.2z" opacity=".95"/>' }
};
export const BRANDS = {
  "facebook":[ "#1877F2","f" ], "google":[ "#4285F4","G" ], "gmail":[ "#EA4335","M" ],
  "netflix":[ "#E50914","N" ], "linkedin":[ "#2E9BDA","in" ], "whatsapp":[ "#25D366","W" ],
  "instagram":[ "#E1306C","Ig" ], "twitter":[ "#FFFFFF","X" ], "x (twitter)":[ "#FFFFFF","X" ], "x":[ "#FFFFFF","X" ],
  "youtube":[ "#FF3B30","Y" ], "spotify":[ "#1DB954","S" ], "telegram":[ "#37AEE2","T" ],
  "discord":[ "#7B83F0","D" ], "tiktok":[ "#FFFFFF","Tk" ], "github":[ "#FFFFFF","Gh" ],
  "amazon":[ "#FF9900","a" ], "apple":[ "#FFFFFF","A" ], "microsoft":[ "#4CC2F0","M" ],
  "proton vpn":[ "#8B7CFF","P" ], "proton":[ "#8B7CFF","P" ], "dribbble":[ "#EA4C89","Dr" ],
  "paypal":[ "#4CC2F0","P" ]
};
