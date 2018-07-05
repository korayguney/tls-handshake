package ocsp.fetcher;

import ocsp.api.OcspFetcher;
import ocsp.builder.Properties;
import ocsp.builder.Property;

/**
 * @author erlend
 */
abstract class AbstractOcspFetcher implements OcspFetcher {

    public static final Property<Integer> TIMEOUT_CONNECT = Property.create(15000);

    public static final Property<Integer> TIMEOUT_READ = Property.create(15000);

    protected final Properties properties;

    protected AbstractOcspFetcher(Properties properties) {
        this.properties = properties;
    }
}
