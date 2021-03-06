PGDMP     "            
        z            platzi-market    13.3    13.3 #    ?           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            ?           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            ?           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            ?           1262    46038    platzi-market    DATABASE     n   CREATE DATABASE "platzi-market" WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE = 'Spanish_Colombia.1252';
    DROP DATABASE "platzi-market";
                postgres    false            ?            1259    46041 
   categorias    TABLE     ?   CREATE TABLE public.categorias (
    id_categoria integer NOT NULL,
    descripcion character varying(45) NOT NULL,
    estado boolean NOT NULL
);
    DROP TABLE public.categorias;
       public         heap    postgres    false            ?            1259    46039    categorias_id_categoria_seq    SEQUENCE     ?   CREATE SEQUENCE public.categorias_id_categoria_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 2   DROP SEQUENCE public.categorias_id_categoria_seq;
       public          postgres    false    201            ?           0    0    categorias_id_categoria_seq    SEQUENCE OWNED BY     [   ALTER SEQUENCE public.categorias_id_categoria_seq OWNED BY public.categorias.id_categoria;
          public          postgres    false    200            ?            1259    46060    clientes    TABLE     ?   CREATE TABLE public.clientes (
    id character varying(20) NOT NULL,
    nombre character varying(40),
    apellidos character varying(100),
    celular numeric,
    direccion character varying(80),
    correo_electronico character varying(70)
);
    DROP TABLE public.clientes;
       public         heap    postgres    false            ?            1259    46070    compras    TABLE     ?   CREATE TABLE public.compras (
    id_compra integer NOT NULL,
    id_cliente character varying(20) NOT NULL,
    fecha timestamp without time zone,
    medio_pago character(1),
    comentario character varying(300),
    estado character(1)
);
    DROP TABLE public.compras;
       public         heap    postgres    false            ?            1259    46068    compras_id_compra_seq    SEQUENCE     ?   CREATE SEQUENCE public.compras_id_compra_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 ,   DROP SEQUENCE public.compras_id_compra_seq;
       public          postgres    false    206            ?           0    0    compras_id_compra_seq    SEQUENCE OWNED BY     O   ALTER SEQUENCE public.compras_id_compra_seq OWNED BY public.compras.id_compra;
          public          postgres    false    205            ?            1259    46081    compras_productos    TABLE     ?   CREATE TABLE public.compras_productos (
    id_compra integer NOT NULL,
    id_producto integer NOT NULL,
    cantidad integer,
    total numeric(16,2),
    estado boolean
);
 %   DROP TABLE public.compras_productos;
       public         heap    postgres    false            ?            1259    46049 	   productos    TABLE       CREATE TABLE public.productos (
    id_producto integer NOT NULL,
    nombre character varying(45),
    id_categoria integer NOT NULL,
    codigo_barras character varying(150),
    precio_venta numeric(16,2),
    cantidad_stock integer NOT NULL,
    estado boolean
);
    DROP TABLE public.productos;
       public         heap    postgres    false            ?            1259    46047    productos_id_producto_seq    SEQUENCE     ?   CREATE SEQUENCE public.productos_id_producto_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 0   DROP SEQUENCE public.productos_id_producto_seq;
       public          postgres    false    203            ?           0    0    productos_id_producto_seq    SEQUENCE OWNED BY     W   ALTER SEQUENCE public.productos_id_producto_seq OWNED BY public.productos.id_producto;
          public          postgres    false    202            7           2604    46044    categorias id_categoria    DEFAULT     ?   ALTER TABLE ONLY public.categorias ALTER COLUMN id_categoria SET DEFAULT nextval('public.categorias_id_categoria_seq'::regclass);
 F   ALTER TABLE public.categorias ALTER COLUMN id_categoria DROP DEFAULT;
       public          postgres    false    201    200    201            9           2604    46073    compras id_compra    DEFAULT     v   ALTER TABLE ONLY public.compras ALTER COLUMN id_compra SET DEFAULT nextval('public.compras_id_compra_seq'::regclass);
 @   ALTER TABLE public.compras ALTER COLUMN id_compra DROP DEFAULT;
       public          postgres    false    205    206    206            8           2604    46052    productos id_producto    DEFAULT     ~   ALTER TABLE ONLY public.productos ALTER COLUMN id_producto SET DEFAULT nextval('public.productos_id_producto_seq'::regclass);
 D   ALTER TABLE public.productos ALTER COLUMN id_producto DROP DEFAULT;
       public          postgres    false    203    202    203            ?          0    46041 
   categorias 
   TABLE DATA           G   COPY public.categorias (id_categoria, descripcion, estado) FROM stdin;
    public          postgres    false    201   M*       ?          0    46060    clientes 
   TABLE DATA           a   COPY public.clientes (id, nombre, apellidos, celular, direccion, correo_electronico) FROM stdin;
    public          postgres    false    204   ?*       ?          0    46070    compras 
   TABLE DATA           _   COPY public.compras (id_compra, id_cliente, fecha, medio_pago, comentario, estado) FROM stdin;
    public          postgres    false    206   ?+       ?          0    46081    compras_productos 
   TABLE DATA           \   COPY public.compras_productos (id_compra, id_producto, cantidad, total, estado) FROM stdin;
    public          postgres    false    207   ?+       ?          0    46049 	   productos 
   TABLE DATA           {   COPY public.productos (id_producto, nombre, id_categoria, codigo_barras, precio_venta, cantidad_stock, estado) FROM stdin;
    public          postgres    false    203   ,       ?           0    0    categorias_id_categoria_seq    SEQUENCE SET     I   SELECT pg_catalog.setval('public.categorias_id_categoria_seq', 8, true);
          public          postgres    false    200            ?           0    0    compras_id_compra_seq    SEQUENCE SET     C   SELECT pg_catalog.setval('public.compras_id_compra_seq', 1, true);
          public          postgres    false    205            ?           0    0    productos_id_producto_seq    SEQUENCE SET     H   SELECT pg_catalog.setval('public.productos_id_producto_seq', 54, true);
          public          postgres    false    202            ;           2606    46046    categorias categorias_pkey 
   CONSTRAINT     b   ALTER TABLE ONLY public.categorias
    ADD CONSTRAINT categorias_pkey PRIMARY KEY (id_categoria);
 D   ALTER TABLE ONLY public.categorias DROP CONSTRAINT categorias_pkey;
       public            postgres    false    201            ?           2606    46067    clientes clientes_pkey 
   CONSTRAINT     T   ALTER TABLE ONLY public.clientes
    ADD CONSTRAINT clientes_pkey PRIMARY KEY (id);
 @   ALTER TABLE ONLY public.clientes DROP CONSTRAINT clientes_pkey;
       public            postgres    false    204            A           2606    46075    compras compras_pkey 
   CONSTRAINT     Y   ALTER TABLE ONLY public.compras
    ADD CONSTRAINT compras_pkey PRIMARY KEY (id_compra);
 >   ALTER TABLE ONLY public.compras DROP CONSTRAINT compras_pkey;
       public            postgres    false    206            C           2606    46085 (   compras_productos compras_productos_pkey 
   CONSTRAINT     z   ALTER TABLE ONLY public.compras_productos
    ADD CONSTRAINT compras_productos_pkey PRIMARY KEY (id_compra, id_producto);
 R   ALTER TABLE ONLY public.compras_productos DROP CONSTRAINT compras_productos_pkey;
       public            postgres    false    207    207            =           2606    46054    productos productos_pkey 
   CONSTRAINT     _   ALTER TABLE ONLY public.productos
    ADD CONSTRAINT productos_pkey PRIMARY KEY (id_producto);
 B   ALTER TABLE ONLY public.productos DROP CONSTRAINT productos_pkey;
       public            postgres    false    203            E           2606    46076    compras fk_COMPRAS_CLIENTES1    FK CONSTRAINT     ?   ALTER TABLE ONLY public.compras
    ADD CONSTRAINT "fk_COMPRAS_CLIENTES1" FOREIGN KEY (id_cliente) REFERENCES public.clientes(id);
 H   ALTER TABLE ONLY public.compras DROP CONSTRAINT "fk_COMPRAS_CLIENTES1";
       public          postgres    false    206    2879    204            G           2606    46091 /   compras_productos fk_COMPRAS_PRODUCTOS_COMPRAS1    FK CONSTRAINT     ?   ALTER TABLE ONLY public.compras_productos
    ADD CONSTRAINT "fk_COMPRAS_PRODUCTOS_COMPRAS1" FOREIGN KEY (id_compra) REFERENCES public.compras(id_compra);
 [   ALTER TABLE ONLY public.compras_productos DROP CONSTRAINT "fk_COMPRAS_PRODUCTOS_COMPRAS1";
       public          postgres    false    2881    207    206            F           2606    46086 1   compras_productos fk_COMPRAS_PRODUCTOS_PRODUCTOS1    FK CONSTRAINT     ?   ALTER TABLE ONLY public.compras_productos
    ADD CONSTRAINT "fk_COMPRAS_PRODUCTOS_PRODUCTOS1" FOREIGN KEY (id_producto) REFERENCES public.productos(id_producto);
 ]   ALTER TABLE ONLY public.compras_productos DROP CONSTRAINT "fk_COMPRAS_PRODUCTOS_PRODUCTOS1";
       public          postgres    false    207    203    2877            D           2606    46055 !   productos fk_PRODUCTOS_CATEGORIAS    FK CONSTRAINT     ?   ALTER TABLE ONLY public.productos
    ADD CONSTRAINT "fk_PRODUCTOS_CATEGORIAS" FOREIGN KEY (id_categoria) REFERENCES public.categorias(id_categoria);
 M   ALTER TABLE ONLY public.productos DROP CONSTRAINT "fk_PRODUCTOS_CATEGORIAS";
       public          postgres    false    203    2875    201            ?   ?   x???	?0Dϫ*\A ??㐓. ??4??̮dH9)?U??h}?y<f????Y?o3CBV??@=k?Y??H-K?Y?sHf??[>#??=??!l;????Ԗ?C??)?X???	Q???s???k.?      ?   ?   x?-?1
?0 g????d???Ph?/??iC;$/?[??ʡ?????X??n?=?7??%?[c;&20$?????Y?@??&?Y???0\?4?X?s?Y{!??G??G??????;????J??e?k??EϞ?s5@ ? ?s<
?F)?J4D      ?   0   x?3?4151322?4??4?5??54P04?26?20?t???????? ???      ?   <   x?M??	  ????p?A?˰?#?aWDt?N???GZ?H?)?@,4hDI?O??????      ?   H  x?}?Mr?F?ףS?	\???%C?Ƕ?H+J??Qc
*?AB??FY?r],? ??"?zz^?{??|H??Dg?~꒐?W*??(RZ???PU??ٝ(q??u?????:??Prd?eF3???R(*MK<2?h??fȈ?zH??ˠ?V?n??Jq??? ʊ˼z?\*z?sPIa?
??n3?Lд?*?^?XS???:??
~????moǮ%A̞k??ֱ?3??X!GBJ"?????X%}ֆ?fj?k0(uYo??m??!8?*Cz,d?R??w?uJ8??/?%U??!?p^K???:??Kg?%?gJUH?]????1z?Q`(#?ˡ?@u?0g???F83?????????ܜ??d$???ܔjN??U??i??<?N?O??
??mj?$?G??????قq=??D?R?J????N?'????]?7	(????JR?!??a??J???}??*?P?;??n???=??
/Ųn?s?U?ý?,???Ѯ`p@????th??!?"}?|Û?????0 ?
0?ևAO?2?f????ؙ/ܺ??z????K?????4u??{n?W??????u5{???0?&?E?G~???h?E1zN?ik?}G+H???a#?t???w܏?XF?bbaE???'T?j??\????????m?O?{?U^bc?1????i??m?y?t???s???????S?H?Jky8?rh:??cpw?dNP??\I,?2s???3X??&q???h1??K?|????y??}ƅ?O?)??0?"??Nq%d?????3?Y??Z02?U?d?]{F?Mծ???Թ?e?????1?тtͬ?h?B?????^?V???8???"F??ߖ}?A??????]????7G
"??}'>f???Ts??n<j?????????%?+q?>i=d?V?6n?h???|?F??Ǵy?:??\?D}܃Q?#???aW???I?*I??M??RP?Y?w?"㼣O??v????dU?g?]-?N&??"???O???_?e?#?????*?h?=???]??޲\j?yM_??؞}Ԕ?6Q??? 3?J????Jaoْ[??y???7 ???IPI	??YX }?!???ȣ??????}899?4?Ū     