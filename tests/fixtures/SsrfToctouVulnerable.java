import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

final class SsrfToctouVulnerable {
    Object fetchPreview(HttpServletRequest request) throws Exception {
        String target = request.getParameter("url");
        return new URL(target).openConnection();
    }

    Object fetchSpringPreview(@RequestParam("url") String target) throws Exception {
        return new URL(target).openStream();
    }

    Object fetchSpringPath(@PathVariable String target) throws Exception {
        return new URL(target).openConnection();
    }

    String readExisting(Path path) throws Exception {
        if (Files.exists(path)) {
            return Files.readString(path);
        }
        return "";
    }

    Object openExisting(File file) throws Exception {
        if (file.exists()) {
            return new FileInputStream(file);
        }
        return null;
    }
}
