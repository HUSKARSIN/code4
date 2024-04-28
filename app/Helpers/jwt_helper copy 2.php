<?php

use Firebase\JWT\JWT;
use App\Models\UserModel;

function getJWTFromRequest($authenticationHeader): string
{
    if (is_null($authenticationHeader)) {
        throw new Exception('Missing or invalid JWT in request');
    }
    return explode(' ', $authenticationHeader)[1];
}

function validateJWTFromRequest(string $encodedToken)
{
    $key = \Config\Services::getSecretKey();

    // Construer:eto stdClass con la propiedad 'algorithm'
    $options = new stdClass();
    $options->algorithm = 'HS256';

    // Decodificar el token con las opciones
    $decodedToken = \Firebase\JWT\JWT::decode($encodedToken, $key, $options);

    // Continuar con el procesamiento del token
    $userModel = new UserModel();
    $userModel->findUserByEmailAddress($decodedToken->email);
}

function getSignedJWTForUser(string $email): string
{
    $issuedAtTime = time();
    $tokenTimeToLive = getenv('JWT_TIME_TO_LIVE');
    $tokenExpiration = $issuedAtTime + $tokenTimeToLive;
    $payload = [
        'email' => $email,
        'iat' => $issuedAtTime,
        'exp' => $tokenExpiration
    ];
    $jwt = \Firebase\JWT\JWT::encode($payload, \Config\Services::getSecretKey(), 'HS256');
    return $jwt;
}


