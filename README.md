# kotlin-web-maven-spring-jsp-register-3des-encrypt-scrypt-encoded

## Description
A springboot secure web app with jsp support.
Three roles are defined; USER, ADMIN, and SUPER. All roles
can access pages `/home`, `/login`, and `/about`. Only USER
can access `/user` and ADMIN only `/admin` whereas SUPER can
navigate to either and have its own `/super`. Each role
has an action USER=VIEW ONLY, ADMIN=READ/WRITE, SUPER=CREATE.
All password are encrypted with 3DES and encoded with scrypt
to insure strong passwords.

Uses a 256 byte AES generated key
for the md5 digest password.

## Tech stack
- kotlin
- maven
  - springboot
  - jsp
  - bootstrap
  - jquery
  - datatable

## Docker stack
- maven:3-openjdk-17

## To run
`sudo ./install.sh -u`
Available at http://localhost
- Login with id: user and password: pass
- Login with id: admin and password: pass
- Login with id: super and password: pass

## To stop (optional)
`sudo ./install.sh -d`

## For help
`sudo ./install.sh -h`
