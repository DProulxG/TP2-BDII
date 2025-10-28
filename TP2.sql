-- _____ ____ _____ 
--/__ __Y  __\\__  \
--  / \ |  \/|  /  |
--  | | |  __/ _\  |
--  \_/ \_/   /____/
--                  
-- Format: Nom, Prenom - DA
--      1: Proulx-Girard, David - 1240561
--      2: Minville, Mathieu - 2462352

/*Repondez a toutes les questions suivantes et completez les sections TODO, ajouter des captures d'écran de l'exécution dans l'énoncé Word*/

/*Complétez toutes les questions suivantes dans un schéma/utilisateur nommé TP2*/

/*Q1: Implémentez un système sécurisé pour gérer les mots de passe des utilisateurs dans une base de données. */
-- Étape 1 : Complétez le code de création de la table utilisateur*/

-- l'identifiant utilisateur doit être une clé primaire auto-incrémentée.
-- le nom d'utilisateur doit être unique.
-- la date de création doit être automatiquement définie à la date et l'heure actuelles lors de l'insertion d'un nouvel utilisateur.
-- le nombre de tentatives échouées doit être initialisé à 0.
-- tous les champs doivent être obligatoires.
CREATE TABLE utilisateurs (
    utilisateur_id  NUMBER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,     
    nom_utilisateur VARCHAR2(255) UNIQUE NOT NULL,     
    mot_de_passe VARCHAR2(255) NOT NULL,      
    sel  VARCHAR2(255) NOT NULL,             
    nb_tentatives_echouees NUMBER DEFAULT 0,
    date_creation  TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL
);

-- Étape 2 : Créez une fonction pour générer un sel aléatoire, qui prend en paramètre la longueur souhaitée du sel.
CREATE OR REPLACE FUNCTION generer_sel(
    p_longueur IN NUMBER
) RETURN  IS
BEGIN
    --TODO : Utilisez DBMS_random pour générer un sel aléatoire.
END;
/

-- Étape 3 : Créer une fonction pour valider si le mot de passe respecte les critères de sécurité et est assez fort.
-- Prend en paramètre le mot de passe et retourne TRUE si le mot de passe est assez fort, sinon FALSE.
-- Choisissez au moins 3 critères à respecter et expliquez les en commentaire.

--TODO: fonction de validation de mot de passe
    
-- Étape 4 : Créez une fonction qui calcule le hachage d’un mot de passe en utilisant le package DBMS_CRYPTO et l'algorythme SHA-256.
-- Le hachage doit inclure : le mot de passe, et un sel d'au moins 12 caractères généré aléatoirement.*/
-- La fonction lance exception si le mot de passe n'est pas assez fort.
CREATE OR REPLACE FUNCTION obtenir_hash_mot_de_passe(
    p_password IN ,
    p_sel     IN 
) RETURN  IS
BEGIN
    --TODO : calculer un hachage sécurisé.
END;
/

-- Étape 5 : Ajoutez un trigger pour hacher automatiquement les nouveaux mots de passe lors de leur ajout ou de leur modification. 
-- La fonction Génére puis sauvegarder le sel dans la table utilisateur, chaque mot de passe à un sel unique.
-- La fonction doit gérer les exceptions si le mot de passe n'est pas assez fort et annuler l'insertion ou 
-- la mise à jour et afficher un message d'erreur approprié.
CREATE OR REPLACE TRIGGER trigger_hachage_mot_de_passe
--TODO
BEGIN
    --TODO : Appelez la procédure de hash et stocker l'empreinte et le sel.
END;
/

/*Étape 4 : Créez une fonction pour vérifier si le mot de passe donné correspond à l'empreinte enregistré.
-- Prend en paramètre le nom d'utilisateur et le mot de passe.
-- Doit enregistrer le nombre de tentatives de connexion échouées pour chaque utilisateur,
   -- incrémenté de 1 pour chaque échec et remettre à 0 lors d'une réussite.
-- Ne permettre la connexion que si le nombre de tentatives est inférieur à 3.
-- Retourner TRUE si les informations sont correctes sinon FALSE.
*/
CREATE OR REPLACE FUNCTION valider_connexion(
    p_username IN VARCHAR2,
    p_password IN VARCHAR2
) RETURN BOOLEAN AS
BEGIN
    --TODO : Vérifiez le mot de passe.
END;
/

/*Étape 5 : Testez votre solution:
1. ajouter un utilisateur avec un mot de passe invalide
2. ajouter un utilisateur avec un mot de passe valide
3. tester la connexion avec le bon mot de passe
4. tester la connexion avec un mot de passe incorrect plusieurs fois.
5. tester la modification du mot de passe d'un utilisateur existant.
6. ajouter 2 utilisateurs de test avec le meme mot de passe et validez que leurs empreintes sont différentes.
*/
--test
DECLARE
    --TODO 
BEGIN
    --TODO
END;
/


-- Q2: créer une procédure pour vérifier qu'aucune empreinte n'est dupliquée dans la table utilisateurs. 
-- Étape 1: créer une table de journalisation_empreinte_duplique pour enregistrer les doublons.
-- Utiliser un block PL/SQL pour créer la table à partir des type de la table utilisateurs et avec les champs: 
-- log_id (clé primaire, auto-incrémentée), 1_utilisateur_id, 2_utilisateur_id, date_log. 
-- PS: si un type de données change, le script doit toujours fonctionner.



-- Étape 2: créer une procédure nommée verifier_empreintes_dupliquees.
-- La procédure doit rechercher les empreintes dupliquées dans la table utilisateurs.
-- Pour chaque doublon trouvé, la procédure doit: afficher son nom d'utilisateur et son utilisateur_id dans le terminal
-- insérer une entrée dans la table de journalisation_empreinte_duplique avec les informations des deux utilisateurs et la date actuelle.



-- Étape 3: Créez un travail planifié pour exécuter la procédure verifier_empreintes_dupliquees quotidiennement (Recherche sur internet: DBMS_SCHEDULER).



/*Étape 4 : Testez votre solution, à vous de choisir les scénarios de test.
1.

Pour tester vous pouvez désactiver le trigger de hash et insérer des utilisateurs avec les mêmes mot de passe. 
N'oublier pas de réactiver le trigger après vos tests.
*/



