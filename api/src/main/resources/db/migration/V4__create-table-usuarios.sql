create table usuarios(
    id bigint not null auto_increment,
    username varchar(100) not null,
    pass varchar(300) not null,

    primary key(id)
);