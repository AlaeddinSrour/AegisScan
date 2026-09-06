// Static-analysis fixture only.
class Preview {
  Object unsafe(@RequestParam("destination") String destination) {
    return new URL(destination).openStream();
  }

  Object fixed(@RequestParam("destination") String destination) {
    return new URL("https://preview.example.test/static").openStream();
  }
}
