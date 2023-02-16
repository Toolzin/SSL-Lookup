<?php 
$data = [];

if(!empty($_POST)) {
    if(filter_var($_POST['host'], FILTER_VALIDATE_URL)) {
        $_POST['host'] = parse_url($_POST['host'], PHP_URL_HOST);
    }

    /* Check for any errors */
    $required_fields = ['host'];
    foreach($required_fields as $field) {
        if(!isset($_POST[$field]) || (isset($_POST[$field]) && empty($_POST[$field]) && $_POST[$field] != '0')) {
            Alerts::add_field_error($field, l('global.error_message.empty_field'));
        }
    }

    /* Check for an SSL certificate */
    $certificate = get_website_certificate('https://' . $_POST['host']);

    if(!$certificate) {
        Alerts::add_field_error('host', l('tools.ssl_lookup.error_message'));
    }

    if(!Alerts::has_field_errors() && !Alerts::has_errors()) {

        /* Create the new SSL object */
        $ssl = [
            'organization' => $certificate['issuer']['O'],
            'country' => $certificate['issuer']['C'],
            'common_name' => $certificate['issuer']['CN'],
            'start_datetime' => (new \DateTime())->setTimestamp($certificate['validFrom_time_t'])->format('Y-m-d H:i:s'),
            'end_datetime' => (new \DateTime())->setTimestamp($certificate['validTo_time_t'])->format('Y-m-d H:i:s'),
        ];

        $data['result'] = $ssl;

    }
}

$values = [
  'host' => $_POST['host'] ?? '',
  'result' => $data,
];



function get_website_certificate($url) {
    try {
        $domain = parse_url($url, PHP_URL_HOST);

        $get = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => TRUE,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true
            ]
        ]);

        $read = @stream_socket_client('ssl://' . $domain . ':443', $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $get);

        if(!$read || $errstr) return false;

        $cert = stream_context_get_params($read);

        $certInfo = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);

        return empty($certInfo) ? false : $certInfo;

    } catch (\Exception $exception) {
        return false;
    }
}
