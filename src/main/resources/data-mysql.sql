CREATE TABLE IF NOT EXISTS SPRING_SESSION (
   PRIMARY_ID CHAR(36) NOT NULL,
   SESSION_ID CHAR(36) NOT NULL,
   CREATION_TIME BIGINT NOT NULL,
   LAST_ACCESS_TIME BIGINT NOT NULL,
   MAX_INACTIVE_INTERVAL INT NOT NULL,
   EXPIRY_TIME BIGINT NOT NULL,
   PRINCIPAL_NAME VARCHAR(100),
   CONSTRAINT SPRING_SESSION_PK PRIMARY KEY (PRIMARY_ID)
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC;

CREATE TABLE IF NOT EXISTS SPRING_SESSION_ATTRIBUTES (
   SESSION_PRIMARY_ID CHAR(36) NOT NULL,
   ATTRIBUTE_NAME VARCHAR(200) NOT NULL,
   ATTRIBUTE_BYTES BLOB NOT NULL,
   CONSTRAINT SPRING_SESSION_ATTRIBUTES_PK PRIMARY KEY (SESSION_PRIMARY_ID, ATTRIBUTE_NAME),
   CONSTRAINT SPRING_SESSION_ATTRIBUTES_FK FOREIGN KEY (SESSION_PRIMARY_ID) REFERENCES SPRING_SESSION(PRIMARY_ID) ON DELETE CASCADE
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC;


INSERT INTO utilisateur(email, mot_de_passe, admin)
VALUES
("jd@a.com","$2a$10$wXW2wHA2bu1TdQ26p.2UoehWv8m92w88kabSeL.348VqkpWvSt51q",0),
("fb@a.com","$2a$10$wXW2wHA2bu1TdQ26p.2UoehWv8m92w88kabSeL.348VqkpWvSt51q",1);

