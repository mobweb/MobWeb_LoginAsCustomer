<?php

/**
 * Rewrite the Mage_Customer_Model_Observer model to remove the "updating" of the password if a "master" password was used
 *
 * @author    Louis Bataillard <info@mobweb.ch>
 * @package    MobWeb_LoginAsCustomer
 * @copyright    Copyright (c) MobWeb GmbH (https://mobweb.ch)
 */
class MobWeb_LoginAsCustomer_Model_Observer extends Mage_Customer_Model_Observer
{
    /**
     * Upgrade customer password hash when customer has logged in
     *
     * @param Varien_Event_Observer $observer
     */
    public function actionUpgradeCustomerPassword($observer)
    {
        if (Mage::registry(MobWeb_LoginAsCustomer_Helper_Data::SESSION_KEY_LOGIN_AS_CUSTOMER)) {
            Mage::unregister(MobWeb_LoginAsCustomer_Helper_Data::SESSION_KEY_LOGIN_AS_CUSTOMER);
            return;
        }

        $password = $observer->getEvent()->getPassword();
        $model = $observer->getEvent()->getModel();

        $encryptor = Mage::helper('core')->getEncryptor();
        $hashVersionArray = [
            Mage_Core_Model_Encryption::HASH_VERSION_MD5,
            Mage_Core_Model_Encryption::HASH_VERSION_SHA256,
            Mage_Core_Model_Encryption::HASH_VERSION_SHA512,
            Mage_Core_Model_Encryption::HASH_VERSION_LATEST,
        ];
        $currentVersionHash = null;
        foreach ($hashVersionArray as $hashVersion) {
            if ($encryptor->validateHashByVersion($password, $model->getPasswordHash(), $hashVersion)) {
                $currentVersionHash = $hashVersion;
                break;
            }
        }
        if (Mage_Core_Model_Encryption::HASH_VERSION_SHA256 !== $currentVersionHash) {
            $model->changePassword($password, false);
        }
    }
}
