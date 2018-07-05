package ocsp.fetcher;

import ocsp.api.OcspFetcher;
import ocsp.api.OcspFetcherResponse;
import ocsp.builder.BuildHandler;
import ocsp.builder.Builder;
import ocsp.builder.Properties;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;

/**
 * @author erlend
 */
public class UrlOcspFetcher extends AbstractOcspFetcher {

    /**
     * Builder to create an instance of OcspFetcher using HttpURLConnection for connectivity.
     *
     * @return Prepared fetcher.
     */
    public static Builder<OcspFetcher> builder() {
        return new Builder<>(new BuildHandler<OcspFetcher>() {
            @Override
            public OcspFetcher build(Properties properties) {
                return new UrlOcspFetcher(properties);
            }
        });
    }

    public UrlOcspFetcher(Properties properties) {
        super(properties);
    }

    @Override
    public OcspFetcherResponse fetch(URI uri, byte[] content) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection();
        connection.setConnectTimeout(properties.get(TIMEOUT_CONNECT));
        connection.setReadTimeout(properties.get(TIMEOUT_READ));
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/ocsp-request");
        connection.setRequestProperty("Accept", "application/ocsp-response");
        connection.getOutputStream().write(content);

        return new UrlOcspFetcherResponse(connection);
    }

    private class UrlOcspFetcherResponse implements OcspFetcherResponse {

        private HttpURLConnection connection;

        public UrlOcspFetcherResponse(HttpURLConnection connection) {
            this.connection = connection;
        }

        @Override
        public int getStatus() throws IOException {
            return connection.getResponseCode();
        }

        @Override
        public String getContentType() {
            return connection.getContentType();
        }

        @Override
        public InputStream getContent() throws IOException {
            return connection.getInputStream();
        }

        @Override
        public void close() throws IOException {
            // No action.
        }
    }
}
