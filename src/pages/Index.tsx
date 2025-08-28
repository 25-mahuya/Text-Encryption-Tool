import { useEffect, useMemo, useRef, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "@/hooks/use-toast";
import { Copy, Key, Lock, Shield, Wand2 } from "lucide-react";
import CryptoJS from "crypto-js";

// Helper utilities
const te = new TextEncoder();
const td = new TextDecoder();

const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
};

const base64ToArrayBuffer = (base64: string): ArrayBuffer => {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
};

async function getKeyMaterial(passphrase: string) {
  return crypto.subtle.importKey("raw", te.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
}

async function deriveAesKey(passphrase: string, salt: Uint8Array) {
  const keyMaterial = await getKeyMaterial(passphrase);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100_000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptAESGCM(plaintext: string, passphrase: string) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAesKey(passphrase, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    te.encode(plaintext)
  );
  const combined = new Uint8Array(salt.length + iv.length + new Uint8Array(ciphertext).length);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(ciphertext), salt.length + iv.length);
  return arrayBufferToBase64(combined.buffer);
}

async function decryptAESGCM(encoded: string, passphrase: string) {
  const data = new Uint8Array(base64ToArrayBuffer(encoded));
  const salt = data.slice(0, 16);
  const iv = data.slice(16, 28);
  const ct = data.slice(28);
  const key = await deriveAesKey(passphrase, salt);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return td.decode(plaintext);
}

async function generateRSAKeys() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const pubB64 = arrayBufferToBase64(spki);
  const prvB64 = arrayBufferToBase64(pkcs8);

  const wrap64 = (s: string) => s.match(/.{1,64}/g)?.join("\n") ?? s;
  const publicPem = `-----BEGIN PUBLIC KEY-----\n${wrap64(pubB64)}\n-----END PUBLIC KEY-----`;
  const privatePem = `-----BEGIN PRIVATE KEY-----\n${wrap64(prvB64)}\n-----END PRIVATE KEY-----`;

  return { keyPair, publicPem, privatePem };
}

const Index = () => {
  
  const [mode, setMode] = useState<"encrypt" | "decrypt">("encrypt");
  const [algo, setAlgo] = useState<"AES-GCM" | "RSA-OAEP" | "3DES">("AES-GCM");
  const [input, setInput] = useState("");
  const [secret, setSecret] = useState("");
  const [output, setOutput] = useState("");

  const [rsaKeys, setRsaKeys] = useState<{ publicPem: string; privatePem: string; keyPair: CryptoKeyPair } | null>(null);

  const overlayRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    document.title = "Text Encryption — AES, RSA, 3DES";
    const metaDesc = document.querySelector('meta[name="description"]');
    if (metaDesc) metaDesc.setAttribute("content", "Encrypt and decrypt text with AES‑GCM, RSA‑OAEP, and 3DES in your browser.");
  }, []);

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      document.documentElement.style.setProperty("--spot-x", `${e.clientX}px`);
      document.documentElement.style.setProperty("--spot-y", `${e.clientY}px`);
    };
    window.addEventListener("mousemove", onMove);
    return () => window.removeEventListener("mousemove", onMove);
  }, []);

  const needsSecret = useMemo(() => algo === "AES-GCM" || algo === "3DES", [algo]);

  const onGenerateRsa = async () => {
    const t = toast({ title: "Generating RSA keys", description: "This may take a second..." });
    try {
      const kp = await generateRSAKeys();
      setRsaKeys(kp);
      t.update({ id: t.id, title: "Keys ready", description: "RSA‑OAEP 2048‑bit keys generated." });
    } catch (err) {
      console.error(err);
      t.update({ id: t.id, title: "Failed to generate keys", description: String(err), variant: "destructive" });
    }
  };

  const onAction = async () => {
    try {
      if (!input.trim()) {
        toast({ title: "Nothing to process", description: "Please enter some text." });
        return;
      }

      if (algo === "RSA-OAEP") {
        if (!rsaKeys) await onGenerateRsa();
      }

      if (mode === "encrypt") {
        if (algo === "AES-GCM") {
          if (!secret) return toast({ title: "Passphrase required" });
          const enc = await encryptAESGCM(input, secret);
          setOutput(enc);
        } else if (algo === "3DES") {
          if (!secret) return toast({ title: "Passphrase required" });
          const enc = CryptoJS.TripleDES.encrypt(input, secret).toString();
          setOutput(enc);
        } else {
          if (!rsaKeys) throw new Error("RSA keys not ready");
          const pubDer = base64ToArrayBuffer(rsaKeys.publicPem.replace(/-----.*-----/g, "").replace(/\n/g, ""));
          const publicKey = await crypto.subtle.importKey(
            "spki",
            pubDer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["encrypt"]
          );
          const ct = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, te.encode(input));
          setOutput(arrayBufferToBase64(ct));
        }
      } else {
        if (algo === "AES-GCM") {
          if (!secret) return toast({ title: "Passphrase required" });
          const dec = await decryptAESGCM(input, secret);
          setOutput(dec);
        } else if (algo === "3DES") {
          if (!secret) return toast({ title: "Passphrase required" });
          const bytes = CryptoJS.TripleDES.decrypt(input, secret);
          setOutput(bytes.toString(CryptoJS.enc.Utf8));
        } else {
          if (!rsaKeys) throw new Error("RSA keys not ready");
          const prvDer = base64ToArrayBuffer(rsaKeys.privatePem.replace(/-----.*-----/g, "").replace(/\n/g, ""));
          const privateKey = await crypto.subtle.importKey(
            "pkcs8",
            prvDer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["decrypt"]
          );
          const pt = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, base64ToArrayBuffer(input));
          setOutput(td.decode(pt));
        }
      }
    } catch (err: any) {
      console.error(err);
      toast({
        title: "Operation failed",
        description: err?.message ?? String(err),
        variant: "destructive",
      });
    }
  };

  const onCopy = async () => {
    if (!output) return;
    await navigator.clipboard.writeText(output);
    toast({ title: "Copied", description: "Result copied to clipboard." });
  };

  return (
    <div className="relative min-h-screen overflow-hidden">
      <div ref={overlayRef} className="pointer-gradient" aria-hidden="true" />
      <header className="container py-10">
        <div className="mx-auto max-w-3xl text-center">
          <span className="inline-flex items-center gap-2 rounded-full bg-secondary px-3 py-1 text-sm text-secondary-foreground">
            <Shield size={16} /> Secure by design — all in your browser
          </span>
          <h1 className="mt-4 text-4xl sm:text-5xl font-bold tracking-tight font-playfair animate-fade-in">
            Text Encryption
          </h1>
          <p className="mt-3 text-lg text-muted-foreground">
            Encrypt and decrypt text with AES‑GCM, RSA‑OAEP, and 3DES — no servers, no uploads.
          </p>
        </div>
      </header>

      <main className="container pb-20">
        <Card className="glass-card mx-auto max-w-3xl animate-enter">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Lock className="text-primary" /> Encryption Playground</CardTitle>
            <CardDescription>Choose an algorithm, then encrypt or decrypt text below.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <Tabs value={mode} onValueChange={(v) => setMode(v as any)}>
              <TabsList>
                <TabsTrigger value="encrypt">Encrypt</TabsTrigger>
                <TabsTrigger value="decrypt">Decrypt</TabsTrigger>
              </TabsList>
              <div className="mt-6 grid gap-6 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="algo">Algorithm</Label>
                  <Select value={algo} onValueChange={(v) => setAlgo(v as any)}>
                    <SelectTrigger id="algo"><SelectValue placeholder="Select algorithm" /></SelectTrigger>
                    <SelectContent className="z-50">
                      <SelectItem value="AES-GCM">AES‑GCM (recommended)</SelectItem>
                      <SelectItem value="RSA-OAEP">RSA‑OAEP</SelectItem>
                      <SelectItem value="3DES">3DES (legacy)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                {needsSecret ? (
                  <div className="space-y-2">
                    <Label htmlFor="secret">Passphrase</Label>
                    <Input id="secret" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} placeholder="Enter a strong passphrase" />
                  </div>
                ) : (
                  <div className="space-y-2">
                    <Label>RSA Keys</Label>
                    <div className="flex gap-2">
                      <Button className="hover-scale" variant="secondary" onClick={onGenerateRsa}><Key className="mr-2 h-4 w-4" />Generate</Button>
                      {rsaKeys && <Button className="hover-scale" variant="outline" onClick={() => navigator.clipboard.writeText(rsaKeys.publicPem)}><Copy className="mr-2 h-4 w-4" />Copy Public</Button>}
                      {rsaKeys && <Button className="hover-scale" variant="outline" onClick={() => navigator.clipboard.writeText(rsaKeys.privatePem)}><Copy className="mr-2 h-4 w-4" />Copy Private</Button>}
                    </div>
                  </div>
                )}
              </div>

              <TabsContent value="encrypt" className="mt-6 space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="input">Plaintext</Label>
                  <Textarea id="input" value={input} onChange={(e) => setInput(e.target.value)} placeholder="Type or paste text to encrypt..." rows={6} />
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Button className="hover-scale" onClick={onAction}><Wand2 className="mr-2 h-4 w-4" />Encrypt</Button>
                  <Button className="hover-scale" variant="outline" onClick={() => setInput("")}>Clear</Button>
                </div>
              </TabsContent>

              <TabsContent value="decrypt" className="mt-6 space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="input2">Ciphertext</Label>
                  <Textarea id="input2" value={input} onChange={(e) => setInput(e.target.value)} placeholder="Paste encrypted text to decrypt..." rows={6} />
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Button className="hover-scale" onClick={onAction}><Wand2 className="mr-2 h-4 w-4" />Decrypt</Button>
                  <Button className="hover-scale" variant="outline" onClick={() => setInput("")}>Clear</Button>
                </div>
              </TabsContent>
            </Tabs>

            <div className="space-y-2">
              <Label htmlFor="output">Result</Label>
              <Textarea id="output" value={output} onChange={(e) => setOutput(e.target.value)} placeholder="Your result will appear here..." rows={6} readOnly />
              <div className="flex gap-2">
                <Button className="hover-scale" variant="secondary" onClick={onCopy}><Copy className="mr-2 h-4 w-4" />Copy</Button>
                <Button className="hover-scale" variant="outline" onClick={() => setOutput("")}>Clear</Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </main>
    </div>
  );
};

export default Index;
