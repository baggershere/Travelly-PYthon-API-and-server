CREATE SCHEMA travelly;
SET search_path to travelly; 

CREATE TABLE tr_users (
    username     VARCHAR(100) NOT NULL UNIQUE,
    firstname    VARCHAR(20) NOT NULL,
    lastname     VARCHAR(20) NOT NULL,
    email        VARCHAR(256) NOT NULL UNIQUE,
    dob          DATE NOT NULL,
    admin        BOOLEAN NOT NULL DEFAULT False,
    password 	 VARCHAR(100) NOT NULL,
    recoveryquestion VARCHAR(100) NOT NULL,
    recoveryanswer 	 VARCHAR(100) NOT NULL,	
    salt         VARCHAR(64) NOT NULL,
    r_salt         VARCHAR(64) NOT NULL,
		 CONSTRAINT user_pk PRIMARY KEY (username));

CREATE TABLE tr_session (
    sid          VARCHAR NOT NULL UNIQUE PRIMARY KEY,
    username     VARCHAR(100),
    expires      TIMESTAMP NOT NULL,
    csrf         VARCHAR UNIQUE);

CREATE TABLE tr_r_session (
    r_sid          VARCHAR NOT NULL UNIQUE PRIMARY KEY,
    username     VARCHAR(100),
    expires      TIMESTAMP NOT NULL,
    csrf         VARCHAR UNIQUE);

CREATE TABLE tr_post (
    pid          SERIAL UNIQUE,
    title        TEXT NOT NULL,
    country 	 VARCHAR(20) NOT NULL, 
    author	 VARCHAR(100) NOT NULL,  
    content      TEXT NOT NULL,
    date 	 TIMESTAMP NOT NULL,
		 CONSTRAINT post_pk PRIMARY KEY (pid),
                 CONSTRAINT post_fk1 FOREIGN KEY (author) REFERENCES tr_users(username)
		 ON DELETE CASCADE);
	
CREATE TABLE tr_comment (
    cid          SERIAL,
    pid          INTEGER NOT NULL,
    author	 VARCHAR(100) NOT NULL UNIQUE,  
    content      TEXT NOT NULL,
    date 	 TIMESTAMP NOT NULL,
		 CONSTRAINT comment_pk PRIMARY KEY (cid),
		 CONSTRAINT comment_fk1 FOREIGN KEY (author) REFERENCES tr_users(username)
		 ON DELETE CASCADE,
 		 CONSTRAINT comment_fk2 FOREIGN KEY (pid) REFERENCES tr_post
		 ON DELETE CASCADE );

CREATE TABLE tr_lockout (
    username VARCHAR(50) NOT NULL,
    date TIMESTAMP NOT NULL
);	
CREATE TABLE ip_ban (
    ip_address VARCHAR(50) NOT NULL,
    username VARCHAR(50) NOT NULL,
    date TIMESTAMP NOT NULL
)

