
const RANGE = 95;
const generateKey = () => Array.from({ length: RANGE }, (_, i) => i);

function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

export function nerdEncrypt(text) {
  const key = shuffle(generateKey());
  const body = [...text].map(ch => {
    const c = ch.charCodeAt(0);
    return (c < 32 || c > 126) ? 'XX' : key[c - 32].toString().padStart(2, '0');
  }).join('');
  const keyStr = key.map(n => n.toString().padStart(2, '0')).join('');
  return { cipher: body + keyStr, key };
}

export function nerdDecrypt(cipher) {
  const msgPart = cipher.slice(0, -RANGE * 2);
  const keyPart = cipher.slice(-RANGE * 2);
  const key = keyPart.match(/.{2}/g).map(Number);
  const map = Object.fromEntries(key.map((v, i) => [v.toString().padStart(2, '0'), String.fromCharCode(i + 32)]));
  return msgPart.match(/.{2}/g).map(t => t === 'XX' ? ' ' : (map[t] || ' ')).join('');
} 
