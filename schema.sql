create table contact(
    firstname varchar(100),
    familyname varchar(100),
    gender varchar(10),
    city varchar(30),
    country varchar(30),
    email varchar(30),
    password varchar(30),
    primary key(email)
);

create table loggedinusers(
    email varchar(30),
    token varchar(30),
    primary key(email),
    primary key(token)
);

create table wall_data(
    email varchar(30),
    writer varchar(30),
    content varchar(200)
);
