import java.net.URL;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;

final class SsrfToctouSafe {
    Object fetchHealthcheck() throws Exception {
        return new URL("https://status.example.com/health").openConnection();
    }

    String readFile(Path path) throws Exception {
        try {
            return Files.readString(path);
        } catch (NoSuchFileException exception) {
            return "";
        }
    }
}
