<?php

/**
 * @file
 * dataone.admin.inc
 */

/**
 * Configuration form.
 *
 * @param array $form
 *   The config form
 *
 * @param array $form_state
 *   The form state
 *
 * @return array
 *   The updated form
 */
function dataone_admin_settings($form, &$form_state) {

  $form['main'] = array(
    '#type' => 'fieldset',
    '#title' => t('DataONE Member Node'),
    '#weight' => 1,
  );
  $form['main'][DATAONE_VARIABLE_MEMBER_NODE_IDENTIFIER] = array(
    '#type' => 'textfield',
    '#title' => t('Member Node Identifier'),
    '#prefix' => t('This value will be the identifier for you DataONE Member Node.'),
    '#description' => t('This identifier is made up of only the upper and lower ASCII letters [A-Za-z] and the ASCII digits [0-9].
      This value will be used to build the official DataONE Member Node Identifier in the form of "urn:node:<identifier>".
      For example, if this field\'s value is set to "My_Drupal_Site", your Member Node Identifier will be "urn:node:My_Drupal_Site".
      For more information, see !url.', array('!url' => l('DataONE Node Registration', DATONE_URL_NODE_REGISTRATION, array('attributes' => array('target' => '_blank'))))),
    '#required' => TRUE,
    '#maxlength' => 25,
    '#weight' => 1,
  );
  $form['main'][DATAONE_VARIABLE_API_VERSIONS] = array(
    '#type' => 'checkboxes',
    '#title' => t('Which versions of the API will this site implement?'),
    '#description' => t('This provides felxibility as DataONE releases newer versions of their API.'),
    '#options' => _dataone_api_version_options(),
    '#default_value' => array('v1'),
    '#weight' => 2,
  );

  // Include fields for each DataONE API version.
  _dataone_build_api_version_form_fields($form, 3);

  return $form;
}

/**
 * Build the form fields for each possible version of the Member Node API.
 *
 * @param array $form_element
 *   A Drupal form  element array.
 *
 * @param int $weight
 *   The starting weight within the
 */
function _dataone_build_api_version_form_fields(&$form_element, $weight = 10){
  global $base_url;

  // Increment the weight for each API version.
  $weight_counter = $weight;

  $versions = _dataone_api_version_options();
  foreach ($versions as $version_id => $description) {

    // #states input field for determining if a version section should be shown.
    $api_version_visible_input = ':input[name="' . DATAONE_VARIABLE_API_VERSIONS . '[' . $version_id . ']"]';
    $form_element[$version_id] = array(
      '#type' => 'fieldset',
      '#title' => t('@version Settings', array('@version' => $description)),
      '#weight' => $weight_counter,
      '#states' => array(
        'visible' => array(
          $api_version_visible_input => array('checked' => TRUE),
        ),
      ),
    );

    $online = DATAONE_VARIABLE_API_STATUS . $version_id;
    $form_element[$version_id][$online] = array(
      '#type' => 'radios',
      '#title' => t('Member Node Online Status'),
      '#description' => t('This toggle provides a way to turn off access to the Member Node.'),
      '#options' => _dataone_admin_online_options(),
      '#default_value' => 'development',
      '#weight' => 1,
    );

    $endpoint = DATAONE_VARIABLE_API_ENDPOINT . $version_id;
    $form_element[$version_id][$endpoint] = array(
      '#type' => 'textfield',
      '#title' => t('API Endpoint Path'),
      '#description' => t('The relative path you want to use as the Member Node endpoint.'),
      '#default_value' => 'd1/mn/' . $version_id,
      '#field_prefix' => $base_url . '/',
      '#size' => 30,
      '#weight' => 2,
    );

    $max_log_count = DATAONE_VARIABLE_API_MAX_LOG_COUNT . $version_id;
    $form_element[$version_id][$max_log_count] = array(
      '#type' => 'textfield',
      '#title' => t('Maximum number of log entries to return.'),
      '#description' => t('Cap the number of entires the GetLogRecords() method of the DataONE Member Node API can request. Defaults to %default records.', array('%default' => DATAONE_DEFAULT_MAX_LOG_RECORDS)),
      '#default_value' => DATAONE_DEFAULT_MAX_LOG_RECORDS,
      '#element_validate' => 'element_validate_integer_positive',
      '#size' => 5,
      '#weight' => 3,
    );

    // Increment the weight counter fo rthe next section.
    $weight_counter++;
  }
}

/**
 * Get the possible Member Node Online Status options.
 *
 * @return array
 *   Associative array of accepted values for a Member Node's online status.
 */
function _dataone_admin_online_options() {
  $options = &drupal_static(__FUNCTION__);
  if (empty($options)) {
    $options = array(
      'production' => t('!label - This node is tested, ready and available for access.', array('!label' => '<strong>PRODUCTION</strong>')),
      'development' => t('!label - This node is offline for development.', array('!label' => '<strong>DEVELOPMENT</strong>')),
      'off' => t('!label - This node is not accessible to anyone.', array('!label' => '<strong>OFF</strong>')),
    );
  }

  return $options;
}
