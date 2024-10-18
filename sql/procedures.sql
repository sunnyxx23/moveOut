DELIMITER ;;

use moveout;;

DROP PROCEDURE IF EXISTS signup;;
DROP PROCEDURE IF EXISTS user_login;;
DROP PROCEDURE IF EXISTS findByEmail;;

CREATE PROCEDURE signup(
    IN email VARCHAR(255),
    IN hash_pass VARCHAR(255)
)
BEGIN
    INSERT INTO user (email, pass) VALUES (email, hash_pass);
END
;;


CREATE PROCEDURE user_login(
    IN email VARCHAR(255),
    IN pass VARCHAR(255)
)
BEGIN
    SELECT * FROM user WHERE email = email AND pass = pass AND verified = 1;
END
;;


CREATE PROCEDURE findByEmail(
    IN p_email VARCHAR(255)
)
BEGIN
    SELECT * FROM user WHERE email = p_email;
END
;;
