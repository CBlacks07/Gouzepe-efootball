--
-- PostgreSQL database dump
--

-- Dumped from database version 17.5
-- Dumped by pg_dump version 17.5

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Data for Name: players; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.players VALUES ('IBR@93_GZ', 'Ibrahim', 'MEMBRE', '2025-08-22 10:59:42.322807');
INSERT INTO public.players VALUES ('CBlacks_GZ', 'Caringthon', 'MEMBRE', '2025-08-23 15:00:51.166924');
INSERT INTO public.players VALUES ('Akab_GZ', 'Emmanuel', 'MEMBRE', '2025-08-22 14:53:16.196135');
INSERT INTO public.players VALUES ('EmRiCxX_GZ', 'Emeric', 'MEMBRE', '2025-08-22 14:34:21.632291');
INSERT INTO public.players VALUES ('Fuego_GZ
', 'Ephel', 'MEMBRE', '2025-08-22 14:57:21.67618');
INSERT INTO public.players VALUES ('Kem_GZ', 'Mawouko', 'MEMBRE', '2025-08-22 13:19:58.836599');
INSERT INTO public.players VALUES ('KenkNod_GZ', 'Koboyo', 'MEMBRE', '2025-08-22 14:35:56.573512');
INSERT INTO public.players VALUES ('Matrix _GZ
', 'Max', 'MEMBRE', '2025-08-22 13:16:32.067921');
INSERT INTO public.players VALUES ('Walé-GZ', 'Walé', 'MEMBRE', '2025-08-22 14:56:28.415451');
INSERT INTO public.players VALUES ('Zyex_Legend_GZ
', 'Ezechiel', 'MEMBRE', '2025-08-22 14:36:56.467977');
INSERT INTO public.players VALUES ('Fuente_GZ', 'Pierre', 'MEMBRE', '2025-08-22 14:36:15.252212');
INSERT INTO public.players VALUES ('God''s', 'God''sWill', 'INVITE', '2025-08-22 14:37:21.946341');
INSERT INTO public.players VALUES ('Ismo', 'Ismaël', 'INVITE', '2025-08-22 14:30:38.277774');
INSERT INTO public.players VALUES ('Pat', 'Patrice', 'INVITE', '2025-08-22 14:50:52.312468');
INSERT INTO public.players VALUES ('Rod_GZ', 'Folly', 'MEMBRE', '2025-08-22 14:35:13.773809');
INSERT INTO public.players VALUES ('Yousscash_GZ', 'Issifou', 'MEMBRE', '2025-08-22 14:33:12.04592');
INSERT INTO public.players VALUES ('Rius_oyo_GZ', 'Marius', 'MEMBRE', '2025-08-22 14:35:44.448771');
INSERT INTO public.players VALUES ('Cephas', 'Cephas', 'INVITE', '2025-08-23 15:23:41.575944');
INSERT INTO public.players VALUES ('The_One_GZ', 'Fabio', 'MEMBRE', '2025-08-22 14:36:41.563462');


--
-- Data for Name: champion_result; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: draft; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.draft VALUES ('2025-08-23', '{"d1": [{"a1": 5, "a2": 1, "p1": "CBlacks_GZ", "p2": "EmRiCxX_GZ", "r1": 2, "r2": 0}, {"a1": 1, "a2": 2, "p1": "CBlacks_GZ", "p2": "IBR@93_GZ", "r1": 5, "r2": 0}, {"a1": 2, "a2": 2, "p1": "CBlacks_GZ", "p2": "KenkNod_GZ", "r1": 2, "r2": 0}, {"a1": 1, "a2": 2, "p1": "EmRiCxX_GZ", "p2": "IBR@93_GZ", "r1": 2, "r2": 3}, {"a1": 1, "a2": 0, "p1": "EmRiCxX_GZ", "p2": "KenkNod_GZ", "r1": 3, "r2": 0}, {"a1": 2, "a2": 2, "p1": "IBR@93_GZ", "p2": "KenkNod_GZ", "r1": 4, "r2": 3}], "d2": [{"a1": 3, "a2": 2, "p1": "Akab_GZ", "p2": "Rod_GZ", "r1": 0, "r2": 4}, {"a1": 4, "a2": 0, "p1": "Akab_GZ", "p2": "Cephas", "r1": 8, "r2": 1}, {"a1": 0, "a2": 1, "p1": "Akab_GZ", "p2": "Rius_oyo_GZ", "r1": 1, "r2": 5}, {"a1": 1, "a2": 0, "p1": "Akab_GZ", "p2": "Kem_GZ", "r1": 8, "r2": 3}, {"a1": 2, "a2": 1, "p1": "Akab_GZ", "p2": "Walé-GZ", "r1": 1, "r2": 0}, {"a1": 3, "a2": 2, "p1": "Rod_GZ", "p2": "Kem_GZ", "r1": 2, "r2": 1}, {"a1": 0, "a2": 4, "p1": "Rod_GZ", "p2": "Rius_oyo_GZ", "r1": 1, "r2": 0}, {"a1": 3, "a2": 1, "p1": "Rod_GZ", "p2": "Walé-GZ", "r1": 2, "r2": 3}, {"a1": 2, "a2": 2, "p1": "Walé-GZ", "p2": "Kem_GZ", "r1": 4, "r2": 2}, {"a1": 0, "a2": 4, "p1": "Walé-GZ", "p2": "Rius_oyo_GZ", "r1": 2, "r2": 1}, {"a1": 2, "a2": 0, "p1": "Walé-GZ", "p2": "Cephas", "r1": 2, "r2": 1}, {"a1": 2, "a2": 0, "p1": "Rius_oyo_GZ", "p2": "Kem_GZ", "r1": 4, "r2": 1}, {"a1": 4, "a2": 0, "p1": "Rius_oyo_GZ", "p2": "Cephas", "r1": 7, "r2": 1}, {"a1": 5, "a2": 1, "p1": "Kem_GZ", "p2": "Cephas", "r1": 3, "r2": 2}, {"a1": 4, "a2": 0, "p1": "Rod_GZ", "p2": "Cephas", "r1": 4, "r2": 1}], "date": "2025-08-23", "barrage": {"m1": {}, "m2": {}, "m3": {}, "ids": "EmRiCxX_GZ – Akab_GZ", "label": "Affiche : EmRiCxX_GZ – Akab_GZ", "notes": ""}, "champions": {"d1": {"team": "FRANCE"}, "d2": {"team": "FRANCE"}}}', '2025-08-26 12:06:41.140924+00');


--
-- Data for Name: seasons; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.seasons VALUES (2, '"2025-2026"', '2025-08-25 11:21:28.520997+00', NULL, false);


--
-- Data for Name: matchday; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.matchday VALUES ('2025-08-23', 2, '{"d1": [{"a1": 5, "a2": 1, "p1": "CBlacks_GZ", "p2": "EmRiCxX_GZ", "r1": 2, "r2": 0}, {"a1": 1, "a2": 2, "p1": "CBlacks_GZ", "p2": "IBR@93_GZ", "r1": 5, "r2": 0}, {"a1": 2, "a2": 2, "p1": "CBlacks_GZ", "p2": "KenkNod_GZ", "r1": 2, "r2": 0}, {"a1": 1, "a2": 2, "p1": "EmRiCxX_GZ", "p2": "IBR@93_GZ", "r1": 2, "r2": 3}, {"a1": 1, "a2": 0, "p1": "EmRiCxX_GZ", "p2": "KenkNod_GZ", "r1": 3, "r2": 0}, {"a1": 2, "a2": 2, "p1": "IBR@93_GZ", "p2": "KenkNod_GZ", "r1": 4, "r2": 3}], "d2": [{"a1": 3, "a2": 2, "p1": "Akab_GZ", "p2": "Rod_GZ", "r1": 0, "r2": 4}, {"a1": 4, "a2": 0, "p1": "Akab_GZ", "p2": "Cephas", "r1": 8, "r2": 1}, {"a1": 0, "a2": 1, "p1": "Akab_GZ", "p2": "Rius_oyo_GZ", "r1": 1, "r2": 5}, {"a1": 1, "a2": 0, "p1": "Akab_GZ", "p2": "Kem_GZ", "r1": 8, "r2": 3}, {"a1": 2, "a2": 1, "p1": "Akab_GZ", "p2": "Walé-GZ", "r1": 1, "r2": 0}, {"a1": 3, "a2": 2, "p1": "Rod_GZ", "p2": "Kem_GZ", "r1": 2, "r2": 1}, {"a1": 0, "a2": 4, "p1": "Rod_GZ", "p2": "Rius_oyo_GZ", "r1": 1, "r2": 0}, {"a1": 3, "a2": 1, "p1": "Rod_GZ", "p2": "Walé-GZ", "r1": 2, "r2": 3}, {"a1": 2, "a2": 2, "p1": "Walé-GZ", "p2": "Kem_GZ", "r1": 4, "r2": 2}, {"a1": 0, "a2": 4, "p1": "Walé-GZ", "p2": "Rius_oyo_GZ", "r1": 2, "r2": 1}, {"a1": 2, "a2": 0, "p1": "Walé-GZ", "p2": "Cephas", "r1": 2, "r2": 1}, {"a1": 2, "a2": 0, "p1": "Rius_oyo_GZ", "p2": "Kem_GZ", "r1": 4, "r2": 1}, {"a1": 4, "a2": 0, "p1": "Rius_oyo_GZ", "p2": "Cephas", "r1": 7, "r2": 1}, {"a1": 5, "a2": 1, "p1": "Kem_GZ", "p2": "Cephas", "r1": 3, "r2": 2}, {"a1": 4, "a2": 0, "p1": "Rod_GZ", "p2": "Cephas", "r1": 4, "r2": 1}], "barrage": {"m1": {"A": 3, "B": 1}, "m2": {"A": 4, "B": 2}, "m3": {}, "ids": "EmRiCxX_GZ – Akab_GZ", "label": "EmRiCxX_GZ se maintient en D1 · Akab_GZ reste en D2", "notes": "LUC est directement relégué en D2"}, "champions": {"d1": {"id": "CBlacks_GZ", "team": "FRANCE"}, "d2": {"id": "Rius_oyo_GZ", "team": "FRANCE"}, "barrage": {"ids": {"d1": "EmRiCxX_GZ", "d2": "Akab_GZ"}, "label": "EmRiCxX_GZ se maintient en D1 · Akab_GZ reste en D2", "matches": [{"A": 3, "B": 1}, {"A": 4, "B": 2}, {}]}}}', '2025-08-23 22:32:42.998498+00');


--
-- Data for Name: season_totals; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.season_totals VALUES (1, 'current', '[]', false, '2025-08-25 18:06:08.443243');


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.users VALUES (2, 'user@gz', '$2a$10$NVbXjrmiwi0HJZl/dFgrwOzDxJUe0pku7jbwaXtGhF4ldD577K9Z.', 'member', '2025-08-22 12:32:11.970002');
INSERT INTO public.users VALUES (4, 'user1@gz', '$2a$10$ukG6OohaezElzTpkluY.ded2unXsn7eIJ5y.I4ATXBvrMJnU7PCXm', 'member', '2025-08-22 17:16:12.351776');
INSERT INTO public.users VALUES (5, 'admin@gz.local', '$2a$10$SCGLGQcke9tzKhQk3cVZ.OsOAflrLBH8AMY43fbk4/duLqB4OmHsa', 'admin', '2025-08-22 20:00:08.158182');
INSERT INTO public.users VALUES (1, 'admin@gz', '$2a$10$amu0RD7Leykk2ROKsqcQC.AOE7AXnhkGSD4d3LaxNiK5hvrsR5KLu', 'admin', '2025-08-22 10:33:58.882307');


--
-- Name: season_totals_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.season_totals_id_seq', 72, true);


--
-- Name: seasons_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.seasons_id_seq', 2, true);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.users_id_seq', 5, true);


--
-- PostgreSQL database dump complete
--

