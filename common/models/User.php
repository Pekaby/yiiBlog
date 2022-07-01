<?php

namespace common\models;

use Yii;
use yii\base\NotSupportedException;
use yii\behaviors\TimestampBehavior;
use yii\db\ActiveRecord;
use yii\web\IdentityInterface;

/**
 * This is the model class for table "users".
 *
 * @property int $id
 * @property string|null $name
 * @property string|null $username
 * @property string|null $email
 * @property string|null $password
 * @property string|null $salt
 * @property string|null $auth_key
 * @property string|null $email_key
 * @property int $time
 * @property int|null $status
 */
class User extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'users';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['username', 'email', 'password', 'salt', 'auth_key', 'email_key'], 'string'],
            [['time', 'status'], 'integer'],
            [['name'], 'string', 'max' => 255],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'id' => 'ID',
            'name' => 'Name',
            'username' => 'Username',
            'email' => 'Email',
            'password' => 'Password',
            'salt' => 'Salt',
            'auth_key' => 'Auth_Key',
            'email_key' => 'Email_Key',
            'time' => 'Time',
            'status' => 'Status',
        ];
    }
    
    /**
     * findIdentity
     *
     * @param  mixed $id
     * @return void
     */
    public static function findIdentity($id)
    {
        return static::findOne($id);
    }
    
    /**
     * findIdentityByAccessToken
     *
     * @param  mixed $token
     * @param  mixed $type
     * @return void
     */
    public static function findIdentityByAccessToken($token, $type = null)
    {
        return static::findOne(['access_token' => $token]);
    }
    
    /**
     * validateAuthKey
     *
     * check user auth key with model
     * 
     * @param  mixed $authKey
     * @return bool 
     */
    public function validateAuthKey($authKey)
    {
        return $this->auth_key === $authKey;
    }
    
    /**
     * generateSalt
     *
     * generating string(15) for password
     * 
     * @return string
     */
    public function generateSalt()
    {
        return Yii::$app->security->generateRandomString(15);
    }
        
    /**
     * generateAuthKey
     *
     * @return void
     */
    public function generateAuthKey()
    {
        $this->auth_key = Yii::$app->security->generateRandomString();
    }
    
    /**
     * setPassword
     *
     * Creating password hash for savin into db
     * 
     * @param  mixed $password
     * @return void
     */
    public function setPassword($password)
    {
        $this->salt = $this->generateSalt();
        $this->password = Yii::$app->security->generatePasswordHash($this->salt.$password.Yii::$app->params['auth.passwordSalt']);
    }
    
    /**
     * setTime
     *
     * Setting time of creating user
     * 
     * @return int
     */
    public function setTime()
    {
        $this->time = time();
    }
    
    /**
     * getId
     * 
     * @return string
     */
    public function getId()
    {
        return $this->getPrimaryKey();
    }
    
    /**
     * getAuthKey
     *
     * @return string
     */
    public function getAuthKey()
    {
        return $this->auth_key;
    }
    
    /**
     * validatePassword
     *
     * @return bool
     */
    public function validatePassword()
    {
        return Yii::$app->security->validatePassword($this->salt.$this->password.Yii::$app->params['auth.passwordSalt'], $this->password_hash);
    }
}