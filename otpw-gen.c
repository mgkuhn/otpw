/*
 * One-time password generator
 *
 * Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/>
 *
 * $Id: otpw-gen.c,v 1.9 2003-08-31 20:51:34 mgk25 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <termios.h>
#include <assert.h>
#include <termios.h>
#include "conf.h"
#include "md.h"


#define NL "\r\n"               /* new line sequence in password list output */
#define HEADER_LINES  4       /* lines printed in addition to password lines */
#define MAX_PASSWORDS 1000                /* maximum length of password list */
#define CHALLEN 3                       /* number of characters in challenge */
#define HBUFLEN (CHALLEN + OTPW_HLEN + 1)

/*
 * A list of common English four letter words. It has not been checked
 * particularly well for being free of rude words or trademarks, but
 * that shouldn't be a problem as users should keep them secret anyway.
 */

char word[2048][4] = {
  "abel","able","ably","acer","aces","acet","ache","acid","acne","acre",
  "acts","adam","adds","aden","afar","aged","ages","aide","aids","aims",
  "airs","airy","ajar","akin","alan","alas","alec","ales","alex","alix",
  "ally","alma","alps","also","alto","amen","ames","amid","amis","amos",
  "amps","anal","andy","anew","ange","angy","anna","anne","ante","anti",
  "ants","anus","anya","aoun","apes","apex","apse","arab","arch","arcs",
  "ards","area","aria","arid","arms","army","arts","asda","asia","asks",
  "atom","atop","audi","aung","aunt","aura","auto","avid","aviv","avon",
  "away","awry","axed","axes","axis","axle","aziz","baba","babe","baby",
  "bach","back","bade","bags","bail","bait","bake","baku","bald","bale",
  "bali","ball","balm","band","bang","bank","bans","bare","bark","barn",
  "barr","bars","bart","base","bash","bass","bath","bats","bays","bcci",
  "bdda","bead","beak","beam","bean","bear","beat","beck","bede","beds",
  "beef","been","beep","beer","bees","begs","bell","belt","bend","benn",
  "bent","berg","bert","best","beta","beth","bets","bias","bids","biff",
  "bike","bile","bill","bind","bins","bird","birk","birt","bite","bits",
  "blah","blew","blip","blob","bloc","blot","blow","blue","blur","boar",
  "boat","bodo","body","boer","bogs","boil","bold","bolt","bomb","bond",
  "bone","bonn","bono","bony","book","boom","boon","boot","bore","borg",
  "born","boro","boss","both","bout","bowe","bowl","bows","boyd","boys",
  "brad","bran","bras","brat","bray","bred","brew","brim","brom","bros",
  "brow","buck","buds","buff","bugs","bulb","bulk","bull","bump","bums",
  "bunk","buns","buoy","burn","burr","burt","bury","bush","bust","busy",
  "butt","buys","buzz","byre","byte","cabs","cafe","cage","cain","cake",
  "calf","call","calm","came","camp","cane","cans","cape","caps","capt",
  "cara","card","care","carl","caro","carp","carr","cars","cart","casa",
  "case","cash","cask","cast","cats","cave","cdna","cegb","cell","cent",
  "cert","chad","chan","chap","chas","chat","chef","chen","cher","chew",
  "chic","chin","chip","chop","chub","chum","cite","city","clad","clan",
  "claw","clay","cleo","clio","clip","club","clue","cnaa","cnut","coal",
  "coat","coax","coca","code","cohn","coil","coin","coke","cola","cold",
  "cole","coli","colt","coma","comb","come","comp","cone","cons","cook",
  "cool","cope","cops","copy","cord","core","cork","corn","corp","cose",
  "cost","cosy","cots","coun","coup","cove","cows","cpre","cpsu","cpus",
  "crab","crag","crap","cray","creb","crew","crim","crop","crow","crux",
  "cruz","csce","cuba","cube","cubs","cues","cuff","cult","cunt","cups",
  "curb","curd","cure","curl","curt","cute","cuts","daak","dada","dads",
  "daft","dahl","dais","dale","daly","dame","damn","damp","dams","dana",
  "dane","dank","dare","dark","dart","dash","data","date","dave","davy",
  "dawn","days","daze","dead","deaf","deal","dean","dear","debt","deck",
  "deed","deep","deer","deft","defy","dell","demo","deng","dent","deny",
  "dept","desk","dial","dice","dick","died","dies","diet","digs","dine",
  "ding","dino","dint","dire","dirk","dirt","disc","dish","disk","dive",
  "dock","dodd","does","dogs","dole","doll","dome","done","dons","doom",
  "door","dope","dora","dose","doth","dots","doug","dour","dove","dowd",
  "down","drab","drag","draw","drew","drip","drop","drug","drum","dual",
  "duck","duct","duel","dues","duet","duff","duke","dull","duly","duma",
  "dumb","dump","dune","dung","dunn","dusk","dust","duty","dyer","dyes",
  "dyke","each","earl","earn","ears","ease","east","easy","eats","echo",
  "ecsc","eddy","eden","edge","edgy","edie","edit","edna","edta","eels",
  "efta","egan","eggs","egon","egos","eire","ella","else","emil","emit",
  "emma","ends","enid","envy","epic","ercp","eric","erik","esau","esrc",
  "esso","eton","euro","evan","even","ever","evil","ewen","ewes","exam",
  "exit","exon","expo","eyed","eyes","eyre","ezra","face","fact","fade",
  "fads","fags","fail","fair","fake","fall","fame","fand","fans","fare",
  "farm","farr","fast","fate","fats","fawn","faye","fear","feat","feed",
  "feel","fees","feet","fell","felt","fend","fenn","fens","fern","fete",
  "feud","fiat","fife","figs","fiji","file","fill","film","find","fine",
  "finn","fins","fire","firm","fish","fist","fits","five","flag","flak",
  "flap","flat","flaw","flea","fled","flee","flew","flex","flip","flop",
  "flow","floy","flue","flux","foal","foam","foci","foes","foil","fold",
  "folk","fond","font","food","fool","foot","ford","fore","fork","form",
  "fort","foul","four","fowl","fran","frau","fray","fred","free","fret",
  "frog","from","ftse","fuel","fuji","full","fund","funk","furs","fury",
  "fuse","fuss","fyfe","gael","gail","gain","gait","gala","gale","gall",
  "game","gang","gaol","gaps","garb","gary","gash","gasp","gate","gatt",
  "gaul","gave","gays","gaza","gaze","gcse","gear","gels","gems","gene",
  "gens","gent","germ","gets","gift","gigs","gill","gilt","gina","girl",
  "gist","give","glad","glee","glen","glow","glue","glum","goal","goat",
  "gods","goes","goff","gogh","gold","golf","gone","good","gore","gory",
  "gosh","gown","grab","graf","gram","gran","gray","greg","grew","grey",
  "grid","grim","grin","grip","grit","grow","grub","guil","gulf","gull",
  "gulp","gums","gunn","guns","guru","gust","guts","guys","gwen","hack",
  "haig","hail","hair","hale","half","hall","halo","halt","hams","hand",
  "hang","hank","hans","hard","hare","hari","harm","harp","hart","hash",
  "hate","hath","hats","hatt","haul","have","hawk","haze","hazy","head",
  "heal","heap","hear","heat","heck","heed","heel","heir","hela","held",
  "hell","helm","help","hens","herb","herd","here","hero","herr","hers",
  "hess","hibs","hick","hide","high","hike","hill","hilt","hind","hint",
  "hips","hire","hiss","hits","hive","hiya","hmso","hoax","hogg","hold",
  "hole","holt","holy","home","hong","hons","hood","hoof","hook","hoop",
  "hope","hops","horn","hose","host","hour","hove","howe","howl","hrun",
  "hues","huge","hugh","hugo","hulk","hull","hume","hump","hung","hunt",
  "hurd","hurt","hush","huts","hyde","hype","iaea","iago","iain","ibid",
  "iboa","iced","icon","idea","idle","idly","idol","igor","ills","inca",
  "ince","inch","info","inns","insp","into","iona","ions","iowa","iran",
  "iraq","iris","iron","isis","isle","itch","item","ivan","ives","ivor",
  "jack","jade","jail","jake","jams","jane","jars","java","jaws","jazz",
  "jean","jeep","jeff","jerk","jess","jest","jets","jett","jews","jill",
  "jimi","joan","jobs","jock","joel","joey","john","join","joke","jolt",
  "jose","josh","joys","juan","judd","jude","judi","judo","judy","jugs",
  "july","jump","june","jung","junk","jury","just","kahn","kane","kant",
  "karl","karr","kate","kath","katy","katz","kaye","keel","keen","keep",
  "kemp","kent","kept","kerb","kerr","keys","khan","kick","kidd","kids",
  "kiev","kiff","kill","kiln","kilo","kilt","kind","king","kirk","kiss",
  "kite","kits","kiwi","knee","knew","knit","knob","knot","know","knox",
  "koch","kohl","kong","kuhn","kurt","kyle","kyte","labs","lace","lack",
  "lacy","lads","lady","laid","lain","lair","lais","lake","lama","lamb",
  "lame","lamp","land","lane","lang","laos","laps","lard","lark","lass",
  "last","late","lava","lawn","laws","lays","lazy","lead","leaf","leak",
  "lean","leap","lear","leas","lech","lees","left","legs","lend","lens",
  "lent","leon","less","lest","lets","levi","levy","leys","liam","liar",
  "lice","lick","lids","lied","lien","lies","life","lift","like","lili",
  "lily","lima","limb","lime","limp","lina","line","ling","link","lino",
  "lion","lips","lira","lire","lisa","list","live","liza","load","loaf",
  "loan","lobe","loch","lock","loco","loft","logo","logs","lois","lone",
  "long","look","loom","loop","loos","loot","lord","lore","lori","lose",
  "loss","lost","lots","loud","love","lowe","ltte","luce","luch","luck",
  "lucy","ludo","luis","luke","lull","lump","lung","lure","lush","lust",
  "lute","lyle","lyon","mabs","mace","mach","mack","made","maid","mail",
  "main","mait","make","mala","male","mali","mall","malt","mama","mane",
  "mann","mans","manx","many","maps","marc","mare","mark","marr","mars",
  "marx","mary","mash","mask","mass","mast","mate","mats","matt","maud",
  "mayo","maze","mead","meal","mean","meat","meek","meet","mega","melt",
  "memo","mend","mens","menu","mere","mesh","mess","mice","mick","midi",
  "mike","mild","mile","milk","mill","mime","mind","mine","minh","mini",
  "mink","mins","mint","mips","mira","mire","miss","mist","mite","moan",
  "moat","mobs","moby","mock","mode","modi","mold","mole","mona","monk",
  "mono","mont","mood","moon","moor","moot","more","mori","moss","most",
  "moth","mott","move","mrna","much","muck","mugs","muir","mule","mull",
  "mums","muon","muse","must","mute","myra","nacl","naff","nail","name",
  "nana","nape","nasa","nash","nato","nave","navy","neal","near","neat",
  "neck","need","neil","nell","neon","nero","ness","nest","nets","news",
  "next","nice","nick","niki","nile","nina","nine","niro","noah","node",
  "nods","noel","noir","nome","nona","none","noon","nope","nora","norm",
  "nose","note","noun","nova","nowt","nude","null","numb","nunn","nuns",
  "nupe","nuts","oaks","oars","oath","oats","oban","obey","oboe","odds",
  "oecd","offa","ohio","ohms","oils","oily","okay","olds","olga","oman",
  "omar","omen","omit","once","ones","only","onto","onus","oops","opal",
  "opcs","opec","open","oral","orcs","ores","orgy","oslo","otto","ould",
  "ours","oust","outs","oval","oven","over","owed","owen","owes","owls",
  "owns","oxen","pace","pack","pact","pads","page","pahl","paid","pain",
  "pair","pale","pall","palm","pals","pane","pang","pans","papa","para",
  "park","parr","part","pass","past","pate","path","paul","pave","pawn",
  "paws","pays","peak","pear","peas","peat","peck","peel","peer","pegs",
  "peng","penh","penn","pens","pepe","perm","pers","pert","peru","pest",
  "pete","pets","pews","phew","phil","pick","pied","pier","pies","pigs",
  "pike","pile","pill","pine","ping","pink","pins","pint","pipe","pips",
  "pisa","piss","pits","pitt","pity","pius","plan","play","plea","plot",
  "ploy","plug","plum","plus","pods","poem","poet","poke","pole","poll",
  "polo","poly","pomp","pond","pons","pont","pony","pooh","pool","poor",
  "pope","pops","pore","pork","porn","port","pose","posh","posi","post",
  "pots","pour","pram","prat","pray","prep","pres","prey","prim","prix",
  "prof","prop","pros","prow","pubs","puff","pugh","pull","pulp","pump",
  "punk","punt","puny","pups","pure","push","puts","putt","quay","quid",
  "quit","quiz","race","rack","racy","raft","rage","rags","raid","rail",
  "rain","rake","ramp","rams","rang","rank","rape","rapt","rare","rash",
  "rate","rats","rave","rays","rbge","rdbi","read","real","reap","rear",
  "reds","reed","reef","reel","rees","refs","reid","rein","rely","rene",
  "rent","reps","rest","retd","revd","revs","reza","rhee","riba","ribs",
  "rica","rice","rich","rick","rico","ride","rife","rift","riga","rigs",
  "rind","ring","rink","riot","ripe","risc","rise","risk","rita","rite",
  "ritz","riva","rnli","road","roam","roar","robb","robe","rock","rode",
  "rods","role","rolf","roll","roma","rome","roof","rook","room","root",
  "rope","rory","rosa","rose","ross","rosy","rota","roth","rout","rowe",
  "rows","rubs","ruby","ruck","rudd","rude","rugs","ruin","rule","rump",
  "rune","rung","runs","ruse","rush","russ","rust","ruth","ryan","sack",
  "safe","saga","sage","said","sail","sake","sale","salt","same","sand",
  "sane","sang","sank","sans","sara","sash","saul","save","saws","says",
  "sbus","scan","scar","scot","scsi","scum","seal","seam","sean","seas",
  "seat","secs","sect","seed","seek","seem","seen","seep","sees","sega",
  "sejm","self","sell","sema","semi","send","sent","sept","sera","serb",
  "serc","seth","sets","seve","sewn","sexy","shae","shah","shai","sham",
  "shaw","shed","shia","shih","shin","ship","shoe","shop","shot","show",
  "shut","sick","side","sigh","sign","sikh","silk","sill","silt","sims",
  "sine","sing","sink","sins","site","sits","size","skin","skip","skis",
  "skye","slab","slag","slam","slap","slid","slim","slip","slit","slot",
  "slow","slug","slum","slur","slut","smog","smug","snag","snap","snip",
  "snob","snow","snub","snug","soak","soap","soar","sobs","sock","soda",
  "sofa","soft","soho","soil","sold","sole","solo","some","song","sons",
  "sony","soon","soot","sore","sort","soul","soup","sour","sown","sows",
  "soya","span","spar","spat","spec","sped","spin","spit","spot","spun",
  "spur","ssap","stab","stag","stan","star","stay","stem","step","stew",
  "stir","stok","stop","stow","stub","stud","subs","such","suck","sued",
  "suez","suit","sums","sung","sunk","suns","supt","sure","surf","suzi",
  "suzy","swam","swan","swap","sway","swig","swim","tabs","tack","tact",
  "taff","tags","tail","tait","take","tale","talk","tall","tame","tang",
  "tank","tape","taps","tara","tart","task","tate","taut","taxi","teak",
  "teal","team","tear","teas","tech","tecs","teen","tees","tell","tend",
  "tens","tent","term","tess","test","text","thai","than","that","thaw",
  "thee","them","then","theo","they","thin","this","thou","thud","thug",
  "thus","tick","tide","tidy","tied","tier","ties","tile","till","tilt",
  "time","tina","tins","tiny","tips","tire","tito","toad","toby","todd",
  "toes","togo","toil","told","toll","tomb","tome","tone","toni","tons",
  "tony","took","tool","tops","tore","torn","tort","tory","toss","tour",
  "town","toys","tram","trap","tray","tree","trek","trim","trio","trip",
  "trna","trod","trot","troy","true","tsar","tube","tubs","tuck","tuna",
  "tune","tung","turf","turk","turn","tvei","twig","twin","twit","twos",
  "tyne","type","tyre","ucta","uefa","ugly","uist","undo","unit","unix",
  "unto","upon","urea","urge","urgh","used","user","uses","ussr","utah",
  "vain","vale","vane","vans","vary","vase","vass","vast","vats","veal",
  "veil","vein","vent","vera","verb","vern","very","vest","veto","vets",
  "vial","vibe","vice","view","vile","vine","visa","vita","vivo","void",
  "vole","volt","vote","vous","vows","wabi","wacc","wade","wage","wail",
  "wait","wake","walk","wall","walt","wand","wang","want","ward","ware",
  "warm","warn","warp","wars","wary","wash","wasp","watt","wave","wavy",
  "ways","weak","wear","webb","webs","weed","week","weep","weir","well",
  "went","wept","were","west","what","when","whig","whim","whip","whit",
  "whoa","whom","wick","wide","wife","wigs","wild","will","wily","wind",
  "wine","wing","wink","wins","wipe","wire","wiry","wise","wish","with",
  "wits","woes","woke","wolf","womb","wont","wood","wool","word","wore",
  "work","worm","worn","wove","wrap","wren","writ","wyre","yale","yang",
  "yard","yarn","yawn","yeah","year","yell","yoga","yoke","yolk","york",
  "your","yous","yuan","yuri","yves","zach","zack","zapt","zeal","zero",
  "zest","zeta","zeus","zinc","zone","zoom","zoos","zzap"
};

int debug = 0;

/* add the output and time of a shell command to message digest */

void gurgle(md_state *mdp, char *command)
{
  FILE *f;
  char buf[128];
  long len = 0, l;
  struct timeval t;

  f = popen(command, "r");
  gettimeofday(&t, NULL);
  md_add(mdp, (unsigned char *) &t, sizeof(t));
  if (!f) {
    fprintf(stderr, "External entropy source command '%s'\n"
	    "(one of several) failed.\n", command);
    return;
  }
  while (!feof(f) && !ferror(f)) {
    len += l = fread(buf, 1, sizeof(buf), f);
    md_add(mdp, buf, l);
  }
  if (len == 0)
    fprintf(stderr, "External entropy source command '%s'\n"
	    "returned no output.\n", command);
  else
    if (debug)
      fprintf(stderr, "'%s' added %ld bytes.\n", command, len);
  pclose(f);
  gettimeofday(&t, NULL);
  md_add(mdp, (unsigned char *) &t, sizeof(t));
}


/* A random bit generator. Hashes together various sources of entropy
 * to provide a 16 byte high quality random seed */

/* Determine the initial start state of the random bit generator */

void rbg_seed(unsigned char *r)
{
  /* shell commands that provide high entropy output for RNG */
  char *entropy_cmds[] = {
    ENTROPY_CMDS
  };
  char *entropy_env[] = {
    ENTROPY_ENV
  };
  unsigned i;
  md_state md;
  struct {
    clock_t clk;
    pid_t pid;
    uid_t uid;
    pid_t ppid;
  } entropy;
  
  md_init(&md);

  /* get entropy via some shell commands */
  for (i = 0;  i < sizeof(entropy_env)/sizeof(char*); i++)
    putenv(entropy_env[i]);
  for (i = 0; i < sizeof(entropy_cmds)/sizeof(char*); i++)
    gurgle(&md, entropy_cmds[i]);

  /* other minor sources of entropy */
  entropy.clk = clock();
  entropy.uid = getuid();
  entropy.pid = getpid();
  entropy.ppid = getppid();

  md_add(&md, (unsigned char *) &entropy, sizeof(entropy));

  md_close(&md, r);
}


/* Determine the next random bit generator state */

void rbg_iter(unsigned char *r)
{
  md_state md;
  struct timeval t;

  md_init(&md);
  gettimeofday(&t, NULL);
  md_add(&md, (unsigned char *) &t, sizeof(t));
  md_add(&md, r, MD_LEN);
  md_add(&md, "AutomaGic", 9);  /* feel free to change this as a site key */
  md_close(&md, r);
}


/*
 * Transform the first 6*chars bits of the binary string v into a chars
 * character long string s. The encoding is a modification of the MIME
 * base64 encoding where characters with easily confused glyphs are
 * avoided (0 vs O, 1 vs. l vs. I).
 */

void conv_base64(char *s, const unsigned char *v, int chars)
{
  static const char tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk%mnopqrstuvwxyz"
    ":=23456789+/";
  int i, j;
  
  for (i = 0; i < chars; i++) {
    j = (i / 4) * 3;
    switch (i % 4) {
    case 0: *s++ = tab[  v[j]  >>2];                        break;
    case 1: *s++ = tab[((v[j]  <<4) & 0x30) | (v[j+1]>>4)]; break;
    case 2: *s++ = tab[((v[j+1]<<2) & 0x3c) | (v[j+2]>>6)]; break;
    case 3: *s++ = tab[  v[j+2]     & 0x3f];                break;
    }
  }
  *s++ = '\0';
}

/*
 * Normalize a password by removing whitespace etc. and converting
 * l1| -> I, 0 -> O, \ -> /, just like otpw_verify() does
 */
void pwnorm(char *password) {
  char *src, *dst;
  
  src = dst = password;
  while (1) {
    if (*src == 'l' || *src == '1' || *src == '|')
      *dst++ = 'I';
    else if (*src == '0')
      *dst++ = 'O';
    else if (*src == '\\')
      *dst++ = '/';
    else if ((*src >= 'A' && *src <= 'Z') ||
	     (*src >= 'a' && *src <= 'z') ||
	     (*src >= '2' && *src <= '9') ||
	     *src == ':' ||
	     *src == '%' ||
	     *src == '=' ||
	     *src == '+' ||
	     *src == '/')
      *dst++ = *src;
    else if (*src == '\0') {
      *dst++ = *src;
      return;
    }
    src++;
  }
}

#define PW_BASE64  0
#define PW_WORD4   1


/*
 * Convert a random bit sequence into a printable password
 *
 * Input:      v         random bit string
 *             vlen      length of v in bytes
 *             type      0: modified base-64 encoding
 *             entropy   requested minimum entropy of password
 *             buf       buffer for returning zero-terminated output password
 *             buflen    length of buffer in bytes
 *
 * Returns negative value if provided combination of vlen, type,
 * ent and buflen are not adequate, otherwise return length of
 * generated password (excluding terminating '\0').
 *
 * If buf == NULL, return value depends on buflen:
 *
 *  0:  length of password that would have been generated
 *  1:  number of its non-space password characters
 *  2:  actually used entropy if buflen == 2
 *  3:  maximum entropy that can be specified for given vlen
 */
int make_passwd(const unsigned char *v, int vlen, int type, int entropy,
		char *buf, int buflen)
{
  int pwchars;   /* number of characters in password */
  int pwlen;     /* length of password, including whitespace */
  int emax;
  int i, j, k;

  /* calculate length of output and actually used entropy */
  switch (type) {
  case PW_BASE64:
    pwchars = (entropy + 5) / 6;
    entropy = pwchars * 6;
    pwlen = pwchars + (pwchars > 5 ? (pwchars - 1) / 4 : 0);
    emax = ((vlen * 8) / 6) * 6;
    break;
  case PW_WORD4:
    pwchars = 4 * ((entropy + 10) / 11);
    entropy = 11 * ((entropy + 10) / 11);
    pwlen = pwchars + pwchars / 4 - (pwchars > 0);
    emax = ((vlen * 8) / 11) * 11;
    break;
  default:
    return -1;
  }

  if (!buf) {
    switch (buflen) {
    case 0: return pwlen;      /* including spaces */
    case 1: return pwchars;    /* excluding spaces */
    case 2: return entropy;
    case 3: return emax;
    default: return -2;
    }
  }
  if (entropy > vlen * 8)
    return -3;
  if (pwlen >= buflen)
    return -4;

  switch (type) {
  case PW_BASE64:
    conv_base64(buf, v, pwchars);
    /* add spaces every 3-4 chars for readability (Bresenham's algorithm) */
    i = pwchars - 1;
    j = pwlen - 1;
    k = (pwlen - pwchars) / 2;
    while (i >= 0 && j >= 0) {
      buf[j--] = buf[i--];
      if ((k += pwlen - pwchars + 1) >= pwchars && j > 0) {
	buf[j--] = ' ';
	k -= pwchars;
      }
    }
    break;
  case PW_WORD4:
    for (i = 0; i < pwchars/4; i++) {
      k = 0;
      for (j = i * 11; j < (i+1) * 11; j++)
	k = (k << 1) | ((v[j / 8] >> (j % 8)) & 1);
      memcpy(buf + i * 5, word[k], 4);
      buf[i * 5 + 4] = ' ';
    }
    buf[i * 5 - 1] = '\0';
    break;
  default:
    return -1;
  }

  assert((int) strlen(buf) == pwlen);

  return pwlen;
}


int main(int argc, char **argv)
{
  char version[] = "One-Time Password Generator v 1.2 -- Markus Kuhn";
  char usage[] = "%s\n\n%s [options] | lpr\n"
    "\nOptions:\n\n"
    "\t-h <int>\tnumber of output lines (default 60)\n"
    "\t-w <int>\tmax width of output lines (default 79)\n"
    "\t-e <int>\tminimum entropy of each one-time password [bits]\n"
    "\t\t\t(low security: <30, default: 48, high security: >60)\n"
    "\t-p0\t\tpasswords from modified base64 encoding (default)\n"
    "\t-p1\t\tpasswords from English 4-letter words\n"
    "\t-f <filename>\tdestination file for hashes (default: ~/" OTPW_FILE ")\n"
    "\t-d\t\toutput debugging information\n";

  unsigned char r[MD_LEN], h[MD_LEN];
  md_state md;
  int i, j, k;
  struct passwd *pwd = NULL;
  FILE *f;
  char timestr[81], hostname[81], password1[81], password2[81];
  char *fnout = NULL, *fnoutp = "";
  struct termios term, term_old;
  int stdin_is_tty = 0;
  int width = 79, rows = 60 - HEADER_LINES, pwlen, pwchars;
  int entropy = 48, emax, type = PW_BASE64;
  int cols;
  time_t t;
  char *hbuf;

  assert(md_selftest() == 0);
  assert(OTPW_HLEN * 6 < MD_LEN * 8);
  assert(OTPW_HLEN >= 8);

  /* read command line arguments */
  for (i = 1; i < argc; i++) {
    if (argv[i][0] == '-')
      for (j = 1; j > 0 && argv[i][j] != 0; j++)
        switch (argv[i][j]) {
        case 'h':
	  if (++i >= argc) {
	    fprintf(stderr, "Specify number of lines output after option -h "
		    "(e.g., \"-h 50\")!\n");
	    exit(1);
	  }
	  rows = atoi(argv[i]) - HEADER_LINES;
	  if (rows <= 0) {
	    fprintf(stderr, "Specify not less than %d lines "
		    "(to leave room for header)!\n", HEADER_LINES + 1);
	    exit(1);
	  }
          j = -1;
          break;
        case 'w':
	  if (++i >= argc) {
	    fprintf(stderr, "Specify maximum line length after option -w "
		    "(e.g., \"-l 50\")!\n");
	    exit(1);
	  }
	  width = atoi(argv[i]);
	  if (width < 64) {
	    fprintf(stderr, "Specify not less than 64 character "
		    "wide lines!\n");
	    exit(1);
	  }
          j = -1;
          break;
	case 'e':
	  if (++i >= argc) {
	    fprintf(stderr, "Specify minimum entropy (bits) after option -e "
		    "(e.g., \"-e 64\")!\n");
	    exit(1);
	  }
	  entropy = atoi(argv[i]);
          j = -1;
          break;
        case 'p':
	  if (strlen(argv[i]+j) == 2  &&
	      argv[i][j+1] >= '0' && argv[i][j+1] <= '1')
	    type = argv[i][j+1] - '0';
	  else {
	    fprintf(stderr, "Unknown password format option '-%s'!\n",
		    argv[i]+j);
	    exit(1);
	  }
	  j = -1;
          break;
        case 'f':
	  if (++i >= argc) {
	    fprintf(stderr, "Specify filename after option -f!\n");
	    exit(1);
	  }
          fnout = argv[i];
	  j = -1;
          break;
	case 'd':
	  debug = 1;
	  break;
	default:
          fprintf(stderr, usage, version, argv[0]);
          exit(1);
        }
    else {
      fprintf(stderr, usage, version, argv[0]);
      exit(1);
    }
  }

  /* determine password length */
  pwlen   = make_passwd(NULL, MD_LEN/2, type, entropy, NULL, 0);
  pwchars = make_passwd(NULL, MD_LEN/2, type, entropy, NULL, 1);
  
  /* check whether entropy is ok */
  emax = make_passwd(NULL, MD_LEN/2, type, entropy, NULL, 3);
  if (entropy < EMIN || entropy > emax) {
    fprintf(stderr, "Entropy must be in the range %d to %d bits!\n", EMIN,
	    emax);
    exit(1);
  }

  cols = (width + 2) / (CHALLEN + 1 + pwlen + 2);
  if (rows * cols > 1000)
    rows = 1000 / cols;

  if (debug)
    fprintf(stderr, "pwlen=%d, pwchars=%d, emax=%d, cols=%d, rows=%d\n",
	    pwlen, pwchars, emax, cols, rows);

  if (!fnout) {
    fnout = OTPW_FILE;
    pwd = getpwuid(getuid());
    if (!pwd) {
      fprintf(stderr, "Can't access your password database entry!\n");
      exit(1);
    }
    /* change to home directory */
    if (chdir(pwd->pw_dir) == 0)
      fnoutp = "~/";
  }

  fprintf(stderr, "Generating random seed ...\n");
  rbg_seed(r);

  fprintf(stderr,
    "\nIf your paper password list is stolen, the thief should not gain\n"
    "access to your account with this information alone. Therefore, you\n"
    "need to memorize and enter below a prefix password. You will have to\n"
    "enter that each time directly before entering the one-time password\n"
    "(on the same line).\n\n"
    "When you log in, a %d-digit password number will be displayed.  It\n"
    "identifies the one-time password on your list that you have to append\n"
    "to the prefix password. If another login to your account is in progress\n"
    "at the same time, several password numbers may be shown and all\n"
    "corresponding passwords have to be appended after the prefix\n"
    "password. Best generate a new password list when you have used up half\n"
    "of the old one.\n\n", CHALLEN);

  /* disable echo if stdin is a terminal */
  if (!tcgetattr(fileno(stdin), &term)) {
    stdin_is_tty = 1;
    term_old = term;
    term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    if (tcsetattr(fileno(stdin), TCSAFLUSH, &term)) {
      perror("tcsetattr");
      exit(1);
    }
  }
  /* check whether there is an old password list, to warn against
   * accidental overwriting */
  f = fopen(fnout, "r");
  if (f) {
    fclose(f);
    fprintf(stderr, "Overwrite existing password list '%s%s' (Y/n)? ",
	    fnoutp, fnout);
    fgets(password1, sizeof(password1), stdin);
    if (password1[0] != '\n' && password1[0] != 'y' && password1[0] != 'Y') {
      if (stdin_is_tty)
	tcsetattr(fileno(stdin), TCSANOW, &term_old);
      fprintf(stderr, "\nAborted.\n");
      exit(1);
    }
    fprintf(stderr, "\n\n");
  }
  /* ask for prefix password */
  fprintf(stderr, "Enter new prefix password: ");
  fgets(password1, sizeof(password1), stdin);
  fprintf(stderr, "\nReenter prefix password: ");
  fgets(password2, sizeof(password2), stdin);
  if (stdin_is_tty)
    tcsetattr(fileno(stdin), TCSANOW, &term_old);
  if (strcmp(password1, password2)) {
    fprintf(stderr, "\nThe two entered passwords were not identical!\n");
    exit(1);
  }
  /* remove newline = last character */
  if (*password1)
    password1[strlen(password1)-1] = 0;

  fprintf(stderr, "\n\nCreating '%s%s'.\n", fnoutp, fnout);
  f = fopen(OTPW_TMP, "w");
  if (!f) {
    fprintf(stderr, "Can't write to '" OTPW_TMP);
    perror("'");
    exit(1);
  }
  chmod(OTPW_TMP, S_IRUSR | S_IWUSR);

  /* write magic code for format identification */
  fprintf(f, OTPW_MAGIC);
  fprintf(f, "%d %d %d %d\n", rows * cols, CHALLEN, OTPW_HLEN,
	  pwchars);
  
  fprintf(stderr, "Generating new one-time passwords ...\n\n");

  /* print header that uniquely identifies this password list */
  time(&t);
  strftime(timestr, 80, "%Y-%m-%d %H:%M", localtime(&t));
  printf("OTPW list generated %s", timestr);
  if (!gethostname(hostname, sizeof(hostname)))
    printf(" on %.*s", (int) sizeof(hostname), hostname);
  printf(NL NL);
  
  hbuf = malloc(rows * cols * HBUFLEN);
  if (!hbuf) {
    fprintf(stderr, "Memory allocation error!\n");
    exit(1);
  }

  for (i = 0; i < rows; i++) {
    for (j = 0; j < cols; j++) {
      k = j * rows + i;
      /* generate new password */
      rbg_iter(r);
      make_passwd(r, MD_LEN, type, entropy, password2, sizeof(password2));
      /* output challenge */
      printf("%03d %s", k, password2);
      printf(j == cols - 1 ? NL : "  ");
      /* hash password1 + pwnorm(password2) and save result */
      md_init(&md);
      md_add(&md, password1, strlen(password1));
      pwnorm(password2);
      md_add(&md, password2, pwchars);
      md_close(&md, h);
      sprintf(hbuf + k * HBUFLEN, "%0*d", CHALLEN, k);
      conv_base64(hbuf + k*HBUFLEN + CHALLEN, h, OTPW_HLEN);
    }
  }

  /* paranoia RAM scrubbing (note that we can't scrub stdout/stdin portably) */
  md_init(&md);
  md_add(&md,
	 "Always clean up all memory that was in contact with secrets!!!!!!",
	 65);
  md_close(&md, h);
  memset(password1, 0xaa, sizeof(password1));
  memset(password2, 0xaa, sizeof(password2));

  /* output all hash values in random permutation order */
  for (k = rows * cols - 1; k >= 0; k--) {
    rbg_iter(r);
    i = k > 0 ? (*(unsigned *) r) % k : 0;
    fprintf(f, "%s\n", hbuf + i*HBUFLEN);
    memcpy(hbuf + i*HBUFLEN, hbuf + k*HBUFLEN, HBUFLEN);
  }

  printf(NL "%*s" NL, (cols*(CHALLEN + 1 + pwlen + 2) - 2)/2 + 50/2,
	 "!!! REMEMBER: Enter the PREFIX PASSWORD first !!!");

  fclose(f);
  if (rename(OTPW_TMP, fnout)) {
    fprintf(stderr, "Can't rename '" OTPW_TMP "' to '%s", fnout);
    perror("'");
    exit(1);
  }
  /* if we overwrite OTPW_FILE, then any remaining lock is now meaningless */
  if (pwd)
    unlink(OTPW_LOCK);

  return 0;
}
