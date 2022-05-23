DROP TABLE IF EXISTS users;
DROP TABLE if exists permissions;
DROP TABLE if exists group_permission;
DROP TABLE if exists groups;

CREATE TABLE groups(
   id bigint(20) NOT NULL PRIMARY KEY,
   name varchar(20) NOT NULL
);

CREATE TABLE permissions(
    id bigint(20) NOT NULL PRIMARY KEY,
    name varchar(20) NOT NULL
);

CREATE TABLE users(
    id bigint(20) NOT NULL PRIMARY KEY,
    login_id varchar(20) NOT NULL,
    passwd   varchar(80) NOT NULL,
    group_id bigint(20),
    FOREIGN KEY (group_id) REFERENCES groups(id)
);


CREATE TABLE group_permission(
    id bigint(20) NOT NULL PRIMARY KEY,
    group_id bigint(20) NOT NULL,
    permission_id bigint(20) ,
    FOREIGN KEY (group_id) REFERENCES groups(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id)
);

