package com.abdo.securityjwt.Utils;

public class JWTUtil {


    public static  final String SECRET="mysecret";
    public static  final String AUTH_HEADER="Authorization";
    public static  final String PREFIX="Bearer ";
    public static  final String REFRESH_PATH="/refreshToken";
    public static  final long EXPIRE_ACCESS_TOKEN=1*60*1000;
    public static  final long EXPIRE_REFRESH_TOKEN=15*60*1000;
}
