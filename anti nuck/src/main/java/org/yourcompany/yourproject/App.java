import fi.iki.elonen.NanoHTTPD;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class App {

    private static final long SIZE_LIMIT = 524288000; // 500MB
    private static final String WEBHOOK_URL = "ur webhookurl";
    private static final Logger logger = Logger.getLogger(App.class.getName());
    private static final String STOP_COMMAND_PASSWORD = "mslxuwu";

    public static void main(String[] args) {
        App app = new App();

        // Start the web server for command handling
        CommandServer commandServer = new CommandServer(8080, app);
        new Thread(commandServer).start();

        // Set up iptables and tc rules
        app.setupIptables();
        app.setupTc();

        // Start monitoring threads
        ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(2);
        executor.submit(new FileDeletionMonitor("/path/to/watch", app));
        executor.submit(new RootActivityMonitor(app));

        // Set up auto-run on boot
        app.createSystemdService();

        System.out.println("AntiNoc System is running...");
    }

    public void setupIptables() {
        try {
            String[] commands = {
                "iptables -A OUTPUT -p tcp --dport 22 -m length --length 0:524288000 -j REJECT",
                "iptables -A INPUT -p tcp --sport 22 -m length --length 0:524288000 -j REJECT"
            };
            for (String cmd : commands) {
                Runtime.getRuntime().exec(cmd);
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Failed to setup iptables", e);
        }
    }

    public void setupTc() {
        try {
            String[] commands = {
                "tc qdisc add dev eth0 root handle 1: htb default 11",
                "tc class add dev eth0 parent 1:1 classid 1:11 htb rate 1000mbit ceil 1000mbit",
                "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip protocol 6 0xff flowid 1:11",
                "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip sport 80 0xffff flowid 1:11"
            };
            for (String cmd : commands) {
                Runtime.getRuntime().exec(cmd);
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Failed to setup tc", e);
        }
    }

    public void logAndNotify(String message) {
        try {
            // Log to file
            Files.write(Paths.get("/var/log/file_deletion.log"), (message + "\n").getBytes(), StandardOpenOption.APPEND);

            // Send to Discord
            sendToDiscord(message);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to log and notify", e);
        }
    }

    public void sendToDiscord(String message) {
        try {
            URL url = new URL(WEBHOOK_URL);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json; utf-8");
            connection.setRequestProperty("Accept", "application/json");
            connection.setDoOutput(true);

            String jsonInputString = "{\"content\": \"" + message + "\"}";

            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = jsonInputString.getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream(), "utf-8"));
            StringBuilder response = new StringBuilder();
            String responseLine;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }
            System.out.println(response.toString());
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to send to Discord", e);
        }
    }

    public void createSystemdService() {
        String serviceContent = "[Unit]\n" +
                "Description=AntiNoc Java Service\n" +
                "After=network.target\n\n" +
                "[Service]\n" +
                "ExecStart=/usr/bin/java -jar /path/to/your/compiled/App.jar\n" +
                "WorkingDirectory=/path/to/your/compiled/\n" +
                "Restart=always\n" +
                "User=your-username\n" +
                "Environment=DISPLAY=:0\n" +
                "Environment=JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64\n\n" +
                "[Install]\n" +
                "WantedBy=multi-user.target\n";

        try (FileWriter fileWriter = new FileWriter("/etc/systemd/system/antinoc.service")) {
            fileWriter.write(serviceContent);
            System.out.println("systemd service file created successfully.");

            // Enable and start the service (you may need to run these commands manually with sudo)
            Runtime.getRuntime().exec("sudo systemctl enable antinoc.service");
            Runtime.getRuntime().exec("sudo systemctl start antinoc.service");

            System.out.println("systemd service enabled and started.");
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Failed to create systemd service", e);
        }
    }

    // Inner class for monitoring file deletions
    static class FileDeletionMonitor implements Runnable {

        private String watchDir;
        private App app;

        public FileDeletionMonitor(String watchDir, App app) {
            this.watchDir = watchDir;
            this.app = app;
        }

        @Override
        public void run() {
            try {
                WatchService watchService = FileSystems.getDefault().newWatchService();
                Path path = Paths.get(watchDir);
                path.register(watchService, StandardWatchEventKinds.ENTRY_DELETE);

                while (true) {
                    WatchKey key = watchService.take();
                    for (WatchEvent<?> event : key.pollEvents()) {
                        WatchEvent.Kind<?> kind = event.kind();

                        if (kind == StandardWatchEventKinds.ENTRY_DELETE) {
                            Path deletedFilePath = Paths.get(watchDir).resolve((Path) event.context());
                            java.io.File deletedFile = deletedFilePath.toFile();
                            if (deletedFile.length() >= SIZE_LIMIT) {
                                String logMessage = "Attempted deletion of large file: " + deletedFilePath;
                                app.logAndNotify(logMessage);
                            }
                        }
                    }
                    key.reset();
                }
            } catch (Exception e) {
                Logger.getLogger(FileDeletionMonitor.class.getName()).log(Level.SEVERE, "Failed to monitor file deletions", e);
            }
        }
    }

    // Inner class for monitoring root activity
    static class RootActivityMonitor implements Runnable {

        private App app;

        public RootActivityMonitor(App app) {
            this.app = app;
        }

        @Override
        public void run() {
            try {
                Process process = Runtime.getRuntime().exec("tail -Fn0 /var/log/audit/audit.log");
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;

                while ((line = reader.readLine()) != null) {
                    if (line.contains("root")) {
                        app.sendToDiscord(line);
                    }
                }
            } catch (Exception e) {
                Logger.getLogger(RootActivityMonitor.class.getName()).log(Level.SEVERE, "Failed to monitor root activity", e);
            }
        }
    }

    // Inner class for the command server
    static class CommandServer extends NanoHTTPD {

        private App app;

        public CommandServer(int port, App app) {
            super(port);
            this.app = app;
        }

        @Override

       
