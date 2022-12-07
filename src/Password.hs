module Password where

import System.Random
import System.Random.Stateful
import Data.Aeson
import qualified Data.Text as T
import qualified Data.ByteString.Lazy.Internal as B
import qualified Data.ByteString.Char8 as BS
import GHC.Generics
import Control.Monad (replicateM)
import Data.String
import Prelude as P
import Foreign.C (CSChar(CSChar))
import Data.Char (digitToInt)
import Data.List.Split as S
import Text.Read (Lexeme(Char))
import qualified Data.Map as M
import Control.Monad.State
import Control.Applicative (Alternative(empty))
import Data.List.NonEmpty (some1)
import Control.Monad.Identity (Identity (Identity, Identity))
import Data.IntMap (findWithDefault)
import Data.ByteString (ByteString)
import Data.Tuple.Select
import Data.Password.Argon2
import System.Directory


-- stack install random/aeson to install the package
-- add the dependency random/aeson in the .cabal file, build-depends under Library

-- packages intalled : random, aeson, text, split, bytestring


type PassWord = [Char]


-- data type for storing all associated password information
data PassWordInfo = PassWordInfo {
    website :: String,
    userName :: String,
    password :: PassWord
} deriving Show

instance FromJSON PassWordInfo where
    parseJSON (Object v) =
        PassWordInfo <$> v .: "website"
                     <*> v .: "userName"
                     <*> v .: "password"
    parseJSON _ = mzero

instance ToJSON PassWordInfo where
    toJSON (PassWordInfo website user password) =
        object ["website" .= website
               ,"userName"    .= user
               ,"password".= password       
        ]


randomIndices :: (MonadIO m, Random a, Num a, Eq a) => a -> a -> [a] -> m [a]
randomIndices 0 len xs = return xs
randomIndices n len xs = do 
                        c <- getStdRandom (randomR (1, len-1))
                        if notElem c xs
                          then randomIndices (n-1) len ([c] ++ xs)
                          else randomIndices n len xs
                    


replace ::  (MonadIO m) => Int -> [Char] -> m [Char]
replace n xs = do
                  c <- getStdRandom (randomR (' ', '~'))
                  let (x, _:ys) = P.splitAt n xs
                  return (x ++ [c] ++ ys)

replaceWithNum ::  (MonadIO m) => Int -> [Char] -> m [Char]
replaceWithNum n xs = do
                  c <- getStdRandom (randomR ('0', '9'))
                  let (x, _:ys) = P.splitAt n xs
                  return (x ++ [c] ++ ys)


indexReplace ::(MonadIO m) => [Int] -> [Char] -> m [Char]
indexReplace [] xs     = return xs
indexReplace (a:as) xs = do                             
                            cur <- replace a xs
                            result <- indexReplace as cur
                            return result

numReplace ::(MonadIO m) => [Int] -> [Char] -> m [Char]
numReplace [] xs     = return xs
numReplace (a:as) xs = do                             
                        cur <- replaceWithNum a xs
                        result <- numReplace as cur
                        return result


listofChars :: Int -> [Char] -> StdGen -> [Char]
listofChars 0 xs g = xs
listofChars n xs g = do
                   let (c, s2) = randomR ('a', 'z') g
                   listofChars (n-1) ([c] ++ xs) s2


-- pass word generation function
-- length of password is between 8 and 16
-- first letter is capitalized
-- rest part is a combination of random characters and integers
passWordGeneration :: (MonadIO m) => m PassWord
passWordGeneration = do 
        first <- getStdRandom (randomR ('A', 'Z'))
        len <- getStdRandom (randomR (8, 15))
        rest <- replicateM len (getStdRandom (randomR ('a', 'z')))
        let password = [first] ++ rest
        indices <- randomIndices 4 len []
        result <- indexReplace indices password
        numIndices <- randomIndices 2 len []
        final <- numReplace numIndices result
        return final

-- Convert the random password into Json format
-- Then write password to a file, use that file as our global search store
-- If a user already has a password on a website, generate a new password for the user
storeLocal :: String -> String -> IO [(String, String, PassWord)]
storeLocal web user = do
    pass <- passWordGeneration
    check <- doesFileExist "src/file.txt"
    contents <- readFile "src/file.txt"
    let list = S.splitOn ",\n" contents
    let temp = map B.packChars list
    let maybe = map (decode) temp :: [Maybe PassWordInfo]
    let res = extractInfo maybe
    let replaced = replacePassWord web user pass res
    when (P.length contents >= 0) $
        writeFile "src/file.txt" (listToString replaced)
    return (convertToTuple replaced)   
        
                  
    -- let exist = searchOverList web user res
    -- if length exist > 0 
    --     then let replaced = replacePassWord web user pass res in
    --          writeToFile (listToString replaced)
    --     else let json = PassWordInfo {website = web, userName = user, password = pass} in
    --          appendFile "src/CSE230/file.txt" ((B.unpackChars (encode json)) ++ "\n")
    --let passencry = mkPassword (T.pack pass)



-- same as above
-- change the user's password for a specific website
changePassWord :: String -> String -> IO [(String, String, PassWord)]
changePassWord web user = do
    pass <- passWordGeneration
    contents <- readFile "src/file.txt"
    let list = S.splitOn ",\n" contents
    let temp = map B.packChars list
    let maybe = map (decode) temp :: [Maybe PassWordInfo]
    let res = extractInfo maybe

    --let passencry = mkPassword (T.pack pass)
    let replaced = replacePassWord web user pass res

    when (P.length contents >= 0) $
        writeFile "src/file.txt" (listToString replaced)
    return (convertToTuple replaced)

-- delete a user's password for a website
deletePassWord :: String -> String -> IO [(String, String, PassWord)]
deletePassWord web user = do
    contents <- readFile "src/file.txt"
    let list = S.splitOn ",\n" contents
    let temp = map B.packChars list
    let maybe = map (decode) temp :: [Maybe PassWordInfo]
    let res = extractInfo maybe
    
    let deleted = deleteHelper web user res

    when (P.length contents >= 0) $
        writeFile "src/file.txt" (listToString deleted)
    return (convertToTuple deleted)

loadFile :: IO [Char]
loadFile = do
    contents <- readFile "src/file.txt"
    return contents

-- search over the json file to find the matched password for a website / user
searchPassWord :: String -> IO [(String, String, PassWord)]
searchPassWord search = do
    contents <- readFile "src/file.txt" 
    let list = S.splitOn ",\n" contents
    let temp = map B.packChars list
    let maybe = map (decode) temp :: [Maybe PassWordInfo]
    let res = extractInfo maybe
    return (searchHelper search res)

    
-- extract PassWordInfo from Maybe
extractInfo :: [Maybe PassWordInfo] -> [PassWordInfo]
extractInfo []     = []
extractInfo (x:xs) = case x of
                        Nothing -> extractInfo xs
                        Just a  -> [a] ++ (extractInfo xs)

-- search helper function
searchHelper ::  String -> [PassWordInfo] -> [(String, String, PassWord)]
searchHelper _      []     = []
searchHelper search (x:xs) = if (T.isInfixOf (T.pack search) (T.pack (website x)))
                                then (website x, userName x, password x): searchHelper search xs
                                else if (T.isInfixOf (T.pack search) (T.pack (userName x)))
                                    then (website x, userName x, password x) : searchHelper search xs
                                    else searchHelper search xs

-- try to find a password in the list of PassWordInfo
-- if succeed, replace it with the new password, and return the list with new password
-- if failed, replace the original list
replacePassWord :: String -> String -> PassWord -> [PassWordInfo] -> [PassWordInfo]
replacePassWord web user newpass []     = [PassWordInfo {website=web, userName = user, password = newpass}]
replacePassWord web user newpass (x:xs) =  if (website x) == web && (userName x) == user
                                            then [PassWordInfo {website = web, userName = user, password = newpass}] ++ xs
                                            else [x] ++ replacePassWord web user newpass xs                                   

-- helper function to convert list of PassWordInfo to String
listToString :: [PassWordInfo] -> String
listToString []     = ""
listToString (x:xs) = ((B.unpackChars (encode x)) ++ ",\n") ++ listToString xs


-- delete a password for a specific website of a user
deleteHelper :: String -> String -> [PassWordInfo] -> [PassWordInfo]
deleteHelper  _   _    []    = []
deleteHelper web user (x:xs) = if (website x) == web && (userName x) == user
                                    then xs
                                    else [x] ++ deleteHelper web user xs

convertToTuple :: [PassWordInfo] -> [(String, String, PassWord)]
convertToTuple []     = []
convertToTuple (x:xs) = (website x, userName x, password x) : convertToTuple xs
 
try = do 
    contents <- readFile "src/file.txt"
    let list = S.splitOn ",\n" contents
    let temp = map B.packChars list
    let maybe = map (decode) temp :: [Maybe PassWordInfo]
    let res = extractInfo maybe
    return res

try1 = [PassWordInfo {website = "Google", userName = "Jesse", password = "OeT0p:tqxIl"},PassWordInfo {website = "Amazon", userName = "Jack", password = "Em@qw?ppwyi"},PassWordInfo {website = "Twitch", userName = "Michal", password = "Bwt z^:ri"},PassWordInfo {website = "Youtube", userName = "Julian", password = "MrarclrR\"Uwz"},PassWordInfo {website = "Youtube", userName = "Julian", password = "Puly n/kljvikp^Rg"},PassWordInfo {website = "Youtube", userName = "Julian", password = "HdcC/laiqynjg7b"},PassWordInfo {website = "Google", userName = "Jesse", password = "Tdn{e/akq6ihn"},PassWordInfo {website = "Google", userName = "Jesse", password = "Kqi}gTswh.#mavxp"},PassWordInfo {website = "Google", userName = "Jesse", password = "ObxtkmflcGwBIPeo"}]

try2 = replacePassWord "Google" "Jesse" "1234324e" try1

tryt :: [(String, String, PassWord)]
tryt = searchHelper "Jesse" try1


keyString = BS.pack "It is a 128-bit key"

substring = T.isInfixOf (T.pack ("Jea")) (T.pack "Jessica")

len = do
     l <- passWordGeneration :: IO [Char]
     return (length l)

ind = ("Google","Jesse","ObxtkmflcGwBIPeo")
ind1 = sel1 (ind)
ind2 = sel2 (ind)
ind3 = sel3 (ind)


l1 = length ("Nd3ggbDMhc,zyx2hu" :: [Char])

-- for testing
teststore0 = storeLocal "Google" "Jesse"
teststore1 = storeLocal "Amazon" "Jack"
teststore2 = storeLocal "Twitch" "Michal"
teststore3 = storeLocal "Youtube" "Julian"
teststore4 = storeLocal "Amazon" "Jesscia"
teststore5 = storeLocal "Youtube" "Julian"
teststore6 = storeLocal "Youtube" "Jeffery"
          

passencry = mkPassword (T.pack "Nd3ggbDMhc,zyx2hu")

showpass = unsafeShowPassword passencry