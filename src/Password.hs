module Password where

import System.Random
import System.Random.Stateful
import Data.Aeson
import qualified Data.Text as T
import qualified Data.ByteString.Lazy.Internal as B
import qualified Data.ByteString.Char8 as BS
import Crypto.Hash
import GHC.Generics
import Control.Monad (replicateM)
import Data.String
import Crypto.Cipher.Types
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
import qualified Data.Text.Encoding as T
import Data.ByteString (ByteString)

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


fourIndices :: (MonadIO m, Random a, Num a, Eq a) => a -> a -> [a] -> m [a]
fourIndices 0 len xs = return xs
fourIndices n len xs = do 
                        c <- getStdRandom (randomR (1, len-1))
                        if notElem c xs
                          then fourIndices (n-1) len ([c] ++ xs)
                          else fourIndices n len xs
                    


replace ::  (MonadIO m) => Int -> [Char] -> m [Char]
replace n xs = do
                  c <- getStdRandom (randomR (' ', '~'))
                  let (x, _:ys) = P.splitAt n xs
                  return (x ++ [c] ++ ys)


indexReplace ::(MonadIO m) => [Int] -> [Char] -> m [Char]
indexReplace [] xs     = return xs
indexReplace (a:as) xs = do 
                            cur <- replace a xs
                            result <- indexReplace as cur
                            return result

 
-- Password Generation
-- Password length is between 8 and 12, first element is a random capitalized letter
-- Rest part is a combination of random characters and integers

-- passWordGen ::(MonadIO m) => StateGenM g -> m Info
-- passWordGen g  = do
--                 -- putStrLn "What is the webiste address?"
--                 -- web <- getLine
--                 -- putStrLn "What is your user name?"
--                 -- user <- getLine
--                 first <- getStdRandom (randomR ('A', 'Z'))
--                 len <- getStdRandom (randomR (8, 16))
--                 -- let try = getStdRandom (randomR (8, 16))  :: IO Int
--                 rest <- replicateM len (getStdRandom (randomR ('a', 'z')))
--                 let passwords = [first] ++ rest
--                 indices <- fourIndices 4 len []
--                 result <- indexReplace (indices) (passwords)  
--                 let info = ("Jesse", ("Google", result))
--                 return info


-- storePassWord :: Info -> State PassWordMap ()
-- storePassWord info = do
--                   map <- get
--                   put (M.insert (fst info) (snd info) map)
          
-- execPassWord :: Info -> PassWordMap -> PassWordMap
-- execPassWord info  = execState (storePassWord info) 



-- printMap :: IO ()
-- printMap  = do
--     e <- passWordGen pureGen
--     putStrLn (show e)

-- b = execPassWord test9 store

-- c = let temp = execPassWord test9 store
--     in execPassWord test10 temp

test0 = do 
           let s1 = mkStdGen 42
           let (first, s2) = randomR ('A', 'Z') s1
           let (len, s3) = randomR (8, 16::Int) s2
          --  let rest = replicateM len (randomR ('a', 'z') s3)
           [first] 

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
        len <- getStdRandom (randomR (8, 16))
        rest <- replicateM len (getStdRandom (randomR ('a', 'z')))
        let password = [first] ++ rest
        indices <- fourIndices 4 len []
        result <- indexReplace indices password
        return result

-- Convert the random password into Json format
-- Then write password to a file, use that file as our global search store
-- If a user already has a password on a website, generate a new password for the user
storeLocal :: String -> String -> IO ()
storeLocal web user = do
    pass <- passWordGeneration
    contents <- readFile "src/file.txt"
    let list = S.splitOn ",\n" contents
    let temp = map B.packChars list
    let maybe = map (decode) temp :: [Maybe PassWordInfo]
    let res = extractInfo maybe
    
    -- let exist = searchOverList web user res
    -- if length exist > 0 
    --     then let replaced = replacePassWord web user pass res in
    --          writeToFile (listToString replaced)
    --     else let json = PassWordInfo {website = web, userName = user, password = pass} in
    --          appendFile "src/CSE230/file.txt" ((B.unpackChars (encode json)) ++ "\n")
    let replaced = replacePassWord web user pass res

    when (P.length contents >= 0) $
        writeFile "src/file.txt" (listToString replaced)

test1 = do
        contents <- readFile "file.txt"
        writeFile "file.txt" "1"

-- if needed, same as above
changePassWord :: String -> String -> IO ()
changePassWord web user = do
    pass <- passWordGeneration
    contents <- readFile "src/file.txt"
    let list = S.splitOn ",\n" contents
    let temp = map B.packChars list
    let maybe = map (decode) temp :: [Maybe PassWordInfo]
    let res = extractInfo maybe

    let replaced = replacePassWord web user pass res

    when (P.length contents >= 0) $
        appendFile "src/file.txt" (listToString replaced)



-- for testing
teststore0 = storeLocal "Google" "Jesse"
teststore1 = storeLocal "Amazon" "Jack"
teststore2 = storeLocal "Twitch" "Michal"
teststore3 = storeLocal "Youtube" "Julian"
teststore4 = storeLocal "whatever" "julian"
teststore5 = storeLocal "Youtube" "Julian"

-- arguments: userName and website
-- search over the Json file and return the matched password
searchPassWord :: String -> String -> IO PassWord
searchPassWord web user = do
    contents <- readFile "src/file.txt"
    let list = S.splitOn ",\n" contents
    let temp = map B.packChars list
    let maybe = map (decode) temp :: [Maybe PassWordInfo]
    let res = extractInfo maybe
    return (searchOverList web user res)

    
-- extract PassWordInfo from Maybe
extractInfo :: [Maybe PassWordInfo] -> [PassWordInfo]
extractInfo []     = []
extractInfo (x:xs) = case x of
                        Nothing -> extractInfo xs
                        Just a  -> [a] ++ (extractInfo xs)

-- search over list of PassWordInfo to find the matching password associated with userName and website
searchOverList :: String -> String -> [PassWordInfo] -> PassWord
searchOverList _ _ []          = []
searchOverList web user (x:xs) = if (website x) == web && (userName x) == user
                                    then password x
                                    else searchOverList web user xs

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


try = do 
    contents <- readFile "src/file.txt"
    let list = S.splitOn ",\n" contents
    let temp = map B.packChars list
    let maybe = map (decode) temp :: [Maybe PassWordInfo]
    let res = extractInfo maybe
    return temp

try1 = [PassWordInfo {website = "Google", userName = "Jesse", password = "Pautgiartmpndya"},PassWordInfo {website = "Amazon", userName = "Jack", password = "Mwycglfmpvquxx"},PassWordInfo {website = "Twitch", userName = "Michal", password = "Ghghhzmanyriaae"},PassWordInfo {website = "Youtube", userName = "Julian", password = "Nkmaqhkjb"}]

try2 = replacePassWord "Google" "Jesse" "1234324e" try1

tryt :: [Char]
tryt = searchOverList "Google" "Jesse" try1


keyString = BS.pack "It is a 128-bit key"
             