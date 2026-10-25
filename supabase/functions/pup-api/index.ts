async function securityCheck(req: Request) {
  if (req.method !== "POST") {
    return { error: "Method not allowed.", status: 405 };
  }

  const body = await req.json().catch(() => ({}));
  const ip = String(body?.ip ?? "").trim();

  if (
    !ip ||
    ip.length > 45 ||
    !/^[0-9a-fA-F:.]+$/.test(ip) ||
    (!ip.includes(".") && !ip.includes(":"))
  ) {
    return { error: "A valid IP address is required.", status: 400 };
  }

  // Validate IPv4 addresses strictly.
  function parseIPv4(value: string): number | null {
    const parts = value.split(".");
    if (parts.length !== 4) return null;

    let result = 0;
    for (const part of parts) {
      if (!/^\d{1,3}$/.test(part)) return null;
      const n = Number(part);
      if (n > 255) return null;
      result = result * 256 + n;
    }
    return result;
  }

  // Expand IPv6 addresses to eight groups.
  function parseIPv6(value: string): bigint | null {
    try {
      let s = value.toLowerCase().split("%")[0];

      if (!s.includes(":")) return null;

      // Convert an embedded IPv4 address to two IPv6 groups.
      if (s.includes(".")) {
        const lastColon = s.lastIndexOf(":");
        if (lastColon < 0) return null;

        const v4 = parseIPv4(s.slice(lastColon + 1));
        if (v4 === null) return null;

        const high = ((v4 >>> 16) & 0xffff).toString(16);
        const low = (v4 & 0xffff).toString(16);
        s = s.slice(0, lastColon + 1) + high + ":" + low;
      }

      const halves = s.split("::");
      if (halves.length > 2) return null;

      const left = halves[0] ? halves[0].split(":") : [];
      const right = halves.length === 2 && halves[1]
        ? halves[1].split(":")
        : [];

      const missing = 8 - left.length - right.length;

      if (
        (halves.length === 1 && missing !== 0) ||
        (halves.length === 2 && missing < 1)
      ) {
        return null;
      }

      const groups = [
        ...left,
        ...Array(halves.length === 2 ? missing : 0).fill("0"),
        ...right,
      ];

      if (
        groups.length !== 8 ||
        groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))
      ) {
        return null;
      }

      return groups.reduce(
        (acc, group) => (acc << 16n) | BigInt(parseInt(group, 16)),
        0n,
      );
    } catch {
      return null;
    }
  }

  function matchesCIDR(ipValue: string, cidr: string): boolean {
    const [network, prefixText] = cidr.split("/");
    if (!network) return false;

    if (ipValue.includes(":")) {
      const address = parseIPv6(ipValue);
      const base = parseIPv6(network);
      if (address === null || base === null) return false;

      const prefix = prefixText === undefined ? 128 : Number(prefixText);
      if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) {
        return false;
      }

      const shift = BigInt(128 - prefix);
      return (address >> shift) === (base >> shift);
    }

    const address = parseIPv4(ipValue);
    const base = parseIPv4(network);
    if (address === null || base === null) return false;

    const prefix = prefixText === undefined ? 32 : Number(prefixText);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
      return false;
    }

    const shift = 32 - prefix;
    return shift === 32
      ? true
      : Math.floor(address / 2 ** shift) ===
        Math.floor(base / 2 ** shift);
  }

  const vpnUrls = ip.includes(":")
    ? [
      "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt",
    ]
    : [
      "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
    ];

  try {
    // Cache the downloaded lists in the running Edge Function.
    const cacheKey = vpnUrls[0];
    const cache = (globalThis as any).__pupVpnCache ??= {};
    const now = Date.now();

    if (!cache[cacheKey] || cache[cacheKey].expiresAt < now) {
      const response = await fetch(cacheKey, {
        headers: { Accept: "text/plain" },
        signal: AbortSignal.timeout(8000),
      });

      if (!response.ok) {
        console.warn("Free VPN list returned status", response.status);
        return {
          error: "VPN detection is temporarily unavailable. Please try again.",
          status: 503,
        };
      }

      const text = await response.text();

      if (!text || text.length > 5_000_000) {
        return {
          error: "The VPN list response was invalid.",
          status: 503,
        };
      }

      const entries = text
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith("#"));

      if (entries.length < 100) {
        return {
          error: "The VPN list could not be verified.",
          status: 503,
        };
      }

      cache[cacheKey] = {
        entries,
        expiresAt: now + 30 * 60 * 1000,
      };
    }

    const entries: string[] = cache[cacheKey].entries;
    const isVpn = entries.some((cidr) => matchesCIDR(ip, cidr));

    return {
      is_proxy: false,
      is_vpn: isVpn,
      is_tor: false,
      source: "free-public-vpn-list",
    };
  } catch (error) {
    console.error(
      "Free VPN list lookup failed:",
      error instanceof Error ? error.message : "unknown error",
    );

    return {
      error: "VPN detection is temporarily unavailable. Please try again.",
      status: 503,
    };
  }
}
