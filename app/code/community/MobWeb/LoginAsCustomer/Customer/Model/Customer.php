<?php

/**
 * Rewrite the customer model to change the validatePassword method to accept our custom passwords.
 *
 * @author    Louis Bataillard <info@mobweb.ch>
 * @package    MobWeb_LoginAsCustomer
 * @copyright    Copyright (c) MobWeb GmbH (https://mobweb.ch)
 */
class MobWeb_LoginAsCustomer_Customer_Model_Customer extends Mage_Customer_Model_Customer
{
     /**
     * Validate the specified password agains the custom passwords as defined in the backend. If this validation
     * fails, pass the password to the parent method.
     *
     * @param string $password
     * @return boolean
     */
    public function validatePassword($password)
    {
        // For security reasons, ignore empty passwords
        if ($password && trim($password)) {

            // Get the custom passwords as defined in the backend
            $passwords = Mage::getStoreConfig('customer/password/mobweb_loginascustomer_passwords');
            if ($passwords) {
                $passwords = preg_split("/\\r\\n|\\r|\\n/", $passwords);

                // If the specified password is in the list of passwords, accept it
                if (in_array($password, $passwords)) {
                    return true;
                }
            }
        }

        // Fall back to the default password validation
        return parent::validatePassword($password);
    }
}
