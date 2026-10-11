package generated;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Loads the platform-injected Ed25519 public key and fails closed when no usable
 * material is present. Both a raw 32-byte key (base64, standard or url-safe) and
 * an X.509 SubjectPublicKeyInfo blob are accepted.
 *
 * 加载平台注入的 Ed25519 公钥；无可用材料时失败闭合。既接受原始 32 字节密钥
 * （base64，标准或 url-safe），也接受 X.509 SPKI 编码。
 */
public final class PlatformKey {
    private PlatformKey() {}

    /** The 12-byte Ed25519 SPKI prefix (AlgorithmIdentifier) for a raw key.
     *  原始密钥的 12 字节 Ed25519 SPKI 前缀。 */
    private static final byte[] SPKI_PREFIX = hex("302a300506032b6570032100");

    public static PublicKey fromEnv() throws Exception {
        String value = System.getenv("AGENT_PLATFORM_PUBLIC_KEY_BASE64");
        if (value == null || value.isBlank()) {
            value = readFile(System.getenv("AGENT_PLATFORM_PUBLIC_KEY_FILE"));
        }
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("AGENT_PLATFORM_PUBLIC_KEY_BASE64 is required");
        }
        return publicKeyFromBase64(value.trim());
    }

    /** Decode a platform public key from the platform-injected material: raw
     * 32-byte base64 or an X.509 SPKI blob. / 从平台注入材料解码公钥：原始
     * 32 字节 base64 或 X.509 SPKI。 */
    public static PublicKey publicKeyFromBase64(String value) throws Exception {
        byte[] raw = decode(value);
        if (raw.length == 32) {
            // Wrap the raw key into its X.509 SubjectPublicKeyInfo form so the
            // JDK KeyFactory accepts it. / 把原始密钥包成 X.509 SPKI 形式。
            byte[] spki = new byte[SPKI_PREFIX.length + 32];
            System.arraycopy(SPKI_PREFIX, 0, spki, 0, SPKI_PREFIX.length);
            System.arraycopy(raw, 0, spki, SPKI_PREFIX.length, 32);
            raw = spki;
        }
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(raw));
    }

    private static String readFile(String path) throws Exception {
        if (path == null || path.isBlank()) {
            return null;
        }
        return Files.readString(Path.of(path.trim()));
    }

    private static byte[] decode(String value) {
        String padded = value + "=".repeat((4 - value.length() % 4) % 4);
        for (Base64.Decoder decoder : java.util.List.of(Base64.getUrlDecoder(), Base64.getDecoder())) {
            try {
                return decoder.decode(padded);
            } catch (IllegalArgumentException ignored) {
                // try the next alphabet / 尝试下一种字母表
            }
        }
        throw new IllegalStateException("AGENT_PLATFORM_PUBLIC_KEY_BASE64 must be an Ed25519 public key");
    }

    private static byte[] hex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }
}
