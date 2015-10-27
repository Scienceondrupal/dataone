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
  global $base_url;

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
      For more information, see @url.', array('@url' => l('DataONE Node Registration', DATONE_URL_NODE_REGISTRATION, array('attributes' => array('target' => '_blank')))),
    '#required' => TRUE,
    '#maxlength' => 25,
    '#weight' => 3,
  );
  $form['main'][DATAONE_VARIABLE_API_VERSIONS] = array(
    '#type' => 'checkboxes',
    '#title' => t('Which versions of the API will this site implement?'),
    '#description' => t('This provides felxibility as DataONE releases newer versions of their API.'),
    '#options' => _dataone_admin_api_version_options(),
    '#default_value' => 'v1',
    '#weight' => 1,
  );

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
function _dataone_build_api_version_form_fields(&$form_element, $weight){
  $versions = _dataone_admin_api_version_options();

  foreach ($versions as $verson_id => $description) {
    $form_element[$verson_id] = array(
      '#type' => 'fieldset',
      '#title' => $description,
      '#weight' => ,
    );

    $online = DATAONE_VARIABLE_API_STATUS . $verson_id;
    $form_element[$verson_id][$online] = array(
      '#type' => 'radios',
      '#title' => t('Member Node Online Status for @desc', array('@desc' => $description)),
      '#description' => t('This toggle provides a way to turn off access to the Member Node.'),
      '#options' => _dataone_admin_online_options(),
      '#default_value' => 'development',
      '#weight' => 1,
    );

    $endpoint = DATAONE_VARIABLE_API_ENDPOINT . $verson_id;
    $form_element[$verson_id][$endpoint] = array(
      '#type' => 'textfield',
      '#title' => t('Drupal API Endpoint Path for @desc', array('@desc' => $description)),
      '#prefix' => $base_url,
      '#description' => t('The relative path you want to use as the Member Node endpoint.'),
      '#default_value' => 'd1/mn/' . $verson_id,
      '#required' => TRUE,
      '#weight' => 2,
    );

    $max_log_count = DATAONE_VARIABLE_API_MAX_LOG_COUNT . $version_id;
    $form_element[$version_id][$max_log_count] = array(
      '#type' => 'textfield',
      '#title' => t('Maximum number of log entries to return.'),
      '#description' => t('Cap the number of entires the GetLogRecords() method of the DataONE Member Node API can request.'),
      '#default_value' => '50',
      '#element_validate' => 'element_validate_integer_positive',
    );
  }
}

/**
 * Get the possible Member Node API versions.
 *
 * @return array
 *   Associative array of possible values for this Member Node's API versions.
 */
function _dataone_admin_api_version_options() {
  $options = &drupal_static(__FUNCTION__);
  if (empty($options)) {
    $options = array(
      'v1' => t('Version 1'),
    );
  }

  return $options;
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
      'production' => t('This node is tested, ready and available for access.'),
      'development' => t('This node is offline for development.'),
      'off' => t('No, make this Member Node not accessible to anyone.'),
    );
  }

  return $options;
}
